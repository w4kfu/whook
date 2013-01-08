#ifndef __WAR_H__
#define __WAR_H__

#include <Windows.h>
#include <stdio.h>

#include "..\src\process.h"
#include "..\src\modules.h"
#include "..\src\info.h"
#include "..\src\memory.h"
#include "..\src\threads.h"
#include "..\src\pestuff.h"
#include "..\src\utils.h"

void launch_war(void);

# define SIG_PLAYER "\x68\x84\x1B\x00\x00"

#endif // __WAR_H__
