
/*
  Copyright (C) 2002  Stanislav Ievlev <inger@altlinux.org>
  Copyright (C) 2002  Dmitry V. Levin <ldv@altlinux.org>

  parent handler

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>

#include "userpasswd.h"

static int
write_loop (int fd, const char *buffer, ssize_t count)
{
	ssize_t offset = 0;

	while (count > 0)
	{
		ssize_t block = write (fd, &buffer[offset], count);

		if (block < 0)
		{
			if (errno == EINTR)
				continue;
			return block;
		}
		if (!block)
			break;
		offset += block;
		count -= block;
	}
	fdatasync(fd);
	return offset;
}

/*
 * parent process
 */
conv_state
do_parent (int master)
{
	conv_state state = CONV_WAIT_CURRENT;
	ssize_t count;
	char   *new_pw = 0;
	char   *current_pw = 0;
	char    masterbuf[BUFSIZ];

	/*
	 * read and parse child output
	 */
	while ((count = read (master, masterbuf, sizeof (masterbuf) - 1)) > 0)
	{
		static const char str_current[] = "Current password:";
		static const char str_sss[] = "Current Password:";
		static const char str_kerberos[] = "Current Kerberos password:";
		static const char str_new[] = "Enter new password:";
		static const char str_sss_new[] = "New Password:";
		static const char str_retype[] = "Re-type new password:";
		static const char str_sss_retype[] = "Reenter new Password:";
        static const char str_sss_failed[] = "Password change failed.";

		masterbuf[count] = '\0';
		write (STDOUT_FILENO, masterbuf, count);

		if (strstr (masterbuf, str_current))
		{
			if (CONV_WAIT_CURRENT == state)
			{
				current_pw = get_current_pw ();
				size_t  len = strlen (current_pw);

				count = write_loop (master, current_pw, len);
				if (count != len)
				{
					error (EXIT_SUCCESS,
					       errno,
					       "write current password to child");
					return CONV_ERR;
				}
				state = CONV_WAIT_NEW;
			} else if (CONV_GOT_KERBEROS == state)
			{
				count = write_loop (master, "\n", 1);
				if (count != 1)
				{
					error (EXIT_SUCCESS,
					       errno,
					       "write empty password after kerberos to child");
					return CONV_ERR;
				}
				state = CONV_WAIT_NEW;
			} else
			{
				return CONV_ERR;
			}
		} else if (strstr (masterbuf, str_sss))
		{
			if (CONV_WAIT_CURRENT == state)
			{
				current_pw = get_current_pw ();
				size_t  len = strlen (current_pw);

				count = write_loop (master, current_pw, len);
				if (count != len)
				{
					error (EXIT_SUCCESS,
					       errno,
					       "write current sss password to child");
					return CONV_ERR;
				}
				state = CONV_GOT_SSS;
			} else if (CONV_WAIT_NEW == state)
			{
				char   *pw = current_pw;
				size_t  len;

				if (pw == 0) {
					error (EXIT_SUCCESS,
					       errno,
					       "bad current password saved for sss");
					return CONV_ERR;
				}
				len = strlen (pw);

				count = write_loop (master, pw, len);
				if (count != len)
				{
					error (EXIT_SUCCESS,
					       errno,
					       "write same sss password as current to child");
					return CONV_ERR;
				}
			} else
			{
				return CONV_ERR;
			}
		} else if (strstr (masterbuf, str_kerberos))
		{
			if (CONV_WAIT_CURRENT == state)
			{
				current_pw = get_current_pw ();
				size_t  len = strlen (current_pw);

				count = write_loop (master, current_pw, len);
				if (count != len)
				{
					error (EXIT_SUCCESS,
					       errno,
					       "write current kerberos password to child");
					return CONV_ERR;
				}
				state = CONV_GOT_KERBEROS;
			} else if (CONV_WAIT_NEW == state)
			{
				char   *pw = current_pw;
				size_t  len;

				if (pw == 0) {
					error (EXIT_SUCCESS,
					       errno,
					       "bad current password saved for kerberos");
					return CONV_ERR;
				}
				len = strlen (pw);

				count = write_loop (master, pw, len);
				if (count != len)
				{
					error (EXIT_SUCCESS,
					       errno,
					       "write same kerberos password as current to child");
					return CONV_ERR;
				}
			} else
			{
				return CONV_ERR;
			}
		} else if (strstr (masterbuf, str_new) || strstr (masterbuf, str_sss_new))
		{
			if (current_pw != 0) {
				memset (current_pw, 0, strlen(current_pw));
				free (current_pw);
				current_pw = 0;
			}
			if ((CONV_WAIT_CURRENT == state)
			    || (CONV_WAIT_NEW == state)
			    || (CONV_GOT_KERBEROS == state)
			    || (CONV_GOT_SSS == state))
			{
				size_t  len;

				new_pw = get_new_pw ();
				len = strlen (new_pw);

				if (write_loop (master, new_pw, len) != len)
				{
					memset (new_pw, 0, len);
					free (new_pw);
					new_pw = 0;
					error (EXIT_SUCCESS,
					       errno,
					       "write new password to child");
					return CONV_ERR;
				}
				state = CONV_WAIT_RETYPE;
			} else if (CONV_WAIT_RETYPE == state)
			{
				return CONV_WAIT_RETYPE;
			} else
			{
				return CONV_ERR;
			}
		} else if (strstr (masterbuf, str_retype) || strstr (masterbuf, str_sss_retype))
		{
			if (CONV_WAIT_RETYPE == state)
			{
				size_t  len;

				if (!new_pw)
					new_pw = get_new_pw ();
				len = strlen (new_pw);

				if (write_loop (master, new_pw, len) != len)
				{
					memset (new_pw, 0, len);
					free (new_pw);
					new_pw = 0;
					error (EXIT_SUCCESS,
					       errno,
					       "write retype password to child");
					return CONV_ERR;
				}
				state = CONV_DONE;
			} else
			{
				return CONV_ERR;
			}
        } else if (strstr (masterbuf, str_sss_failed) && CONV_GOT_SSS == state)
        {
            if (CONV_GOT_SSS == state)
                state = CONV_WAIT_NEW;
            else
            {
                    return CONV_ERR;
            }
        }
	}

	return state;
}
