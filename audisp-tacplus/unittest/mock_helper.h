/* plugin.h - functions from plugin.c. */

/* Copyright (C) 1993-2015 Free Software Foundation, Inc.

   This file is part of GNU Bash, the Bourne Again SHell.

   Bash is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   Bash is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Bash.  If not, see <http://www.gnu.org/licenses/>.
*/

#if !defined (_MOCK_HELPER_H_)
#define _MOCK_HELPER_H_

#include "user_secret.h"

// define USER_SECRET_UT_DEBUG to output UT debug message.
#define USER_SECRET_UT_DEBUG
#if defined (USER_SECRET_UT_DEBUG)
#define debug_printf printf
#else
#define debug_printf
#endif

#define TEST_SCEANRIO_LOAD_USER_SECRET_SETTING  	1

/* Set test scenario for test*/
void set_test_scenario(int scenario);

/* Get test scenario for test*/
int get_test_scenario();

/* Set memory allocate count for test*/
void set_memory_allocate_count(int count);

/* Get memory allocate count for test*/
int get_memory_allocate_count();


#endif /* _MOCK_HELPER_H_ */