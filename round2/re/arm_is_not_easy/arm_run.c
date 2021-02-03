
#include <stdio.h>
#include <string.h>

#define uint unsigned int

// supplied input:
// What is your name?              A                                                                                                                                      
// what is your lucky number?      1221                                                                                                                           
// the password is?                @rm-d0-y0u-kn0w-

uint FUN_000105e0(int param_1)

{
  uint uVar1;
  int local_1b4;
  uint local_1b0;
  int local_1ac;
  uint local_1a8;
  int local_1a4;
  int local_1a0;
  int aiStack412 [100];
  
  local_1b0 = 0;
  local_1b4 = param_1;
  while (0 < local_1b4) {
    aiStack412[local_1b0] = local_1b4 % 10;
    local_1b4 = local_1b4 / 10;
    local_1b0 = local_1b0 + 1;
  }
  if ((local_1b0 & 1) == 0) {
    local_1ac = 0;
    local_1a4 = 0;
    local_1a0 = 0;
    while (local_1a8 = local_1b0 - 1, local_1ac < (int)local_1a8) {
      local_1a4 = local_1a4 + aiStack412[local_1ac];
      local_1a0 = local_1a0 + aiStack412[local_1a8];
      local_1ac = local_1ac + 1;
      local_1b0 = local_1a8;
    }
    uVar1 = (uint)(local_1a4 == local_1a0);
  }
  else {
    uVar1 = 0;
  }
  
  return uVar1;
}



char * FUN_00010768(char *param_1)

{
  char *__src;
  char *pcVar1;
  int local_11c;
  uint local_118;
  char *local_c4 [20];
  int local_74 [2];
  char acStack112 [100];
  
  strcpy(acStack112,param_1);
  local_74[0] = 0x2d;
  __src = strtok(acStack112,(char *)local_74);
  local_11c = 0;
  while (__src != (char *)0x0) {
    pcVar1 = (char *)malloc(0x14);
    local_c4[local_11c] = pcVar1;
    strcpy(local_c4[local_11c],__src);
    local_11c = local_11c + 1;
    __src = strtok((char *)0x0,(char *)local_74);
  }
  local_118 = 0x4d2;
  while (local_118 != 0) {
    if (local_118 == 0x26c7) {
      __src = (char *)strcmp(local_c4[3],"kn0w");
      if (__src == (char *)0x0) {
        local_118 = 0x1bce;
      }
      else {
        local_118 = 0x29a;
      }
    }
    else {
      if (local_118 < 0x26c8) {
        if (local_118 == 0x1bce) {
          __src = (char *)printf("The flag is efiensctf{%s}\n",param_1);
          local_118 = 0;
        }
        else {
          if (local_118 < 0x1bcf) {
            if (local_118 == 0xdd1) {
              __src = (char *)strcmp(local_c4[1],"d0");
              if (__src == (char *)0x0) {
                local_118 = 0xc90;
              }
              else {
                local_118 = 0x29a;
              }
            }
            else {
              if (local_118 < 0xdd2) {
                if (local_118 == 0xc90) {
                  __src = (char *)strcmp(local_c4[2],"y0u");
                  if (__src == (char *)0x0) {
                    local_118 = 0x26c7;
                  }
                  else {
                    local_118 = 0x29a;
                  }
                }
                else {
                  if (local_118 < 0xc91) {
                    if (local_118 == 0x929) {
                      __src = (char *)strcmp(local_c4[0],"@rm");
                      if (__src == (char *)0x0) {
                        local_118 = 0xdd1;
                      }
                      else {
                        local_118 = 0x29a;
                      }
                    }
                    else {
                      if (local_118 < 0x92a) {
                        if (local_118 == 0x29a) {
                          __src = (char *)printf("You are dead wrong");
                          local_118 = 0;
                        }
                        else {
                          if (local_118 == 0x4d2) {
                            if (local_11c == 4) {
                              local_118 = 0x929;
                            }
                            else {
                              local_118 = 0x29a;
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return __src;
}

int main()

{
  void *pvVar1;
  uint iVar2;
  int uStack20;
  void *pvStack16;
  
  pvVar1 = malloc(0x15);
  pvStack16 = malloc(0x15);
  printf("What is your name?\t");
  __isoc99_scanf("%[^\n]%*c",pvVar1);
  printf("what is your lucky number?\t");
  __isoc99_scanf("%d%*c",&uStack20);
  printf("the password is?\t");
  __isoc99_scanf("%[^\n]%*c",pvStack16);
  iVar2 = FUN_000105e0(uStack20);
  if (iVar2 == 0) {
    iVar2 = puts("you are not lucky today");
  }
  else {
    iVar2 = FUN_00010768(pvStack16);
  }
  return 0;
}


