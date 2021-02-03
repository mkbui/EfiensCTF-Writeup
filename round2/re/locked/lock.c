
/* WARNING (jumptable): Unable to track spacebase fully for stack */
/* WARNING: Unable to track spacebase fully for stack */

int __cdecl _main(int _Argc,char **_Argv,char **_Env)

{
  BOOL BVar1;
  size_t sVar2;
  char *_Str;
  uint uVar3;
  char *pcVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  bool bVar8;
  int iVar9;
  char *pcVar10;
  uint uVar11;
  char cVar12;
  int *piVar13;
  int *piVar14;
  int iVar15;
  char *pcVar16;
  int iVar17;
  uint uVar18;
  undefined4 in_stack_fffffdd0;
  int in_stack_fffffdd4;
  char *local_208;
  int local_1f8 [4];
  undefined4 local_1e8;
  undefined4 local_1e4;
  undefined4 local_1e0;
  undefined4 local_1dc;
  undefined4 local_1d8;
  int aiStack468 [9];
  int aiStack432 [72];
  char local_90 [100];
  int local_2c;
  int local_28;
  int local_24;
  int *piStack24;
  
  piStack24 = &_Argc;
  ___main();
  BVar1 = _IsDebuggerPresent@0();
  if (BVar1 != 0) {
    _puts("Don\'t even try!");
    _system("pause");
    _ExitProcess@4(0xffffffff);
  }
  local_208 = "Password, pls: ";
  _printf("%s");
  local_208 = local_90;
  _scanf("%s");
  sVar2 = _strlen(local_90);
  if (sVar2 != 0x24) {
    _puts("Wrong! Try harder next time");
    _system("pause");
    _ExitProcess@4(0);
  }
  iVar9 = 0x24;
  piVar13 = &.data;
  piVar14 = aiStack432 + 0x24;
  while (iVar9 != 0) {

    iVar9 = iVar9 + -1;
    *piVar14 = *piVar13;
    piVar13 = piVar13 + 1;
    piVar14 = piVar14 + 1;
  }
  local_24 = 0;
  while (local_24 < 0x24) {
    aiStack432[local_24] = (int)local_90[aiStack432[local_24 + 0x24]];
    local_24 = local_24 + 1;
  }
  local_28 = 0;
  while (local_28 < 9) {
    aiStack468[local_28] =
         aiStack432[local_28 * 4 + 1] * 0x100 + aiStack432[local_28 * 4] +
         aiStack432[local_28 * 4 + 2] * 0x10000 + aiStack432[local_28 * 4 + 3] * 0x1000000;
    local_28 = local_28 + 1;
  }
  local_1f8[0] = 0x735f5f66;
  local_1f8[1] = 0x646c6c65;
  local_1f8[2] = 0x6270637b;
  local_1f8[3] = 0x6f6f656f;
  local_1e8 = 0x666e7564;
  local_1e4 = 0x5f73656d;
  local_1e0 = 0x7d776965;
  local_1dc = 0x6f307767;
  local_1d8 = 0x765f7274;
  local_2c = 0;
  while (local_2c < 9) {
    if (aiStack468[local_2c] != local_1f8[local_2c]) {
      _puts("Wrong! Try harder next time");
      _system("pause");
      _ExitProcess@4(0);
    }
    local_2c = local_2c + 1;
  }
  _puts("Correct!");
  _system("pause");
  _ExitProcess@4(0);
  if ((__CRT_glob & 2) == 0) {
    iVar9 = __mingw32_init_mainargs();
    return iVar9;
  }
  _Str = _GetCommandLineA@0();
  _strlen(_Str);
  iVar9 = ___chkstk_ms();
  iVar9 = -iVar9;
  iVar15 = (int)*_Str;
  pcVar7 = &stack0xfffffdac + iVar9;
  uVar3 = __CRT_glob & 0x4400 | 0x10;
  if (iVar15 != 0) {
    iVar17 = 0;
    uVar11 = 0;
    uVar18 = 0;
    pcVar16 = pcVar7;
    do {
      _Str = _Str + 1;
      cVar12 = (char)iVar15;
      if (cVar12 < '@') {
        if (cVar12 < '\"') {
switchD_00401948_caseD_2:
          pcVar6 = pcVar7 + uVar11;
          pcVar10 = pcVar7;
          if (uVar11 != 0) {
            do {
              pcVar4 = pcVar7 + 1;
              *pcVar7 = '\\';
              pcVar7 = pcVar4;
              pcVar10 = pcVar6;
            } while (pcVar4 != pcVar6);
          }
          pcVar7 = pcVar10;
          if (uVar18 != 0) goto LAB_004017c8;
          if (*(int *)__mb_cur_max_exref == 1) {
            if ((*(byte *)(*(int *)_pctype_exref + iVar15 * 2) & 0x40) == 0) {
LAB_004017b8:
              if (iVar15 != 9) goto LAB_004017c8;
            }
          }
          else {
            *(undefined4 *)(&stack0xfffffda0 + iVar9) = 0x40;
            *(int *)(&stack0xfffffd9c + iVar9) = iVar15;
            *(undefined4 *)(&stack0xfffffd98 + iVar9) = 0x4017b0;
            iVar5 = __isctype(*(int *)(&stack0xfffffd9c + iVar9),*(int *)(&stack0xfffffda0 +iVar9))
            ;
            if (iVar5 == 0) goto LAB_004017b8;
          }
          if ((pcVar16 < pcVar7) || (iVar17 != 0)) {
            *pcVar7 = '\0';
            *(undefined **)(&stack0xfffffda8 + iVar9) = &stack0xfffffdcc;
            *(undefined4 *)(&stack0xfffffda4 + iVar9) = 0;
            pcVar7 = pcVar16;
            *(uint *)(&stack0xfffffda0 + iVar9) = uVar3;
            uVar3 = uVar3 | 1;
            pcVar16 = pcVar7;
            *(char **)(&stack0xfffffd9c + iVar9) = pcVar7;
            *(undefined4 *)(&stack0xfffffd98 + iVar9) = 0x401827;
            ___mingw_glob(*(char **)(&stack0xfffffd9c + iVar9),*(uint *)(&stack0xfffffda0 +iVar9),
                          *(undefined4 *)(&stack0xfffffda4 + iVar9),
                          *(char ***)(&stack0xfffffda8 + iVar9));
            uVar11 = 0;
            iVar17 = 0;
          }
          else {
            iVar17 = 0;
            uVar11 = 0;
          }
        }
        else {
          iVar5 = (int)uVar11 >> 1;
          switch(iVar15 - 0x22U & 0xff) {
          case 0:
            if (iVar5 != 0) {
              pcVar10 = pcVar7 + iVar5;
              pcVar6 = pcVar7;
              do {
                pcVar4 = pcVar6 + 1;
                *pcVar6 = '\\';
                pcVar6 = pcVar4;
                pcVar7 = pcVar10;
              } while (pcVar4 != pcVar10);
            }
            if ((uVar18 == 0x27) || ((uVar11 & 1) != 0)) {
              *pcVar7 = '\"';
              pcVar7 = pcVar7 + 1;
              uVar11 = 0;
              iVar17 = 1;
            }
            else {
              uVar18 = uVar18 ^ 0x22;
              uVar11 = 0;
              iVar17 = 1;
            }
            break;
          default:
            goto switchD_00401948_caseD_2;
          case 5:
            if ((__CRT_glob & 0x10) == 0) goto switchD_00401948_caseD_2;
            if (iVar5 != 0) {
              pcVar10 = pcVar7 + iVar5;
              pcVar6 = pcVar7;
              do {
                pcVar4 = pcVar6 + 1;
                *pcVar6 = '\\';
                pcVar6 = pcVar4;
                pcVar7 = pcVar10;
              } while (pcVar4 != pcVar10);
            }
            if ((uVar18 == 0x22) || ((uVar11 & 1) != 0)) {
              *pcVar7 = '\'';
              pcVar7 = pcVar7 + 1;
              uVar11 = 0;
              iVar17 = 1;
            }
            else {
              uVar18 = uVar18 ^ 0x27;
              uVar11 = 0;
              iVar17 = 1;
            }
            break;
          case 8:
          case 10:
          case 0x1d:
            goto LAB_00401859;
          }
        }
      }
      else {
        if (cVar12 < '[') goto switchD_00401948_caseD_2;
        switch(iVar15 - 0x5bU & 0xff) {
        case 0:
          if ((__CRT_glob & 0x20) != 0) goto LAB_00401859;
          bVar8 = true;
          if (uVar11 != 0) goto LAB_00401873;
LAB_00401895:
          *pcVar7 = '\x7f';
          pcVar7 = pcVar7 + 1;
          break;
        case 1:
          if (uVar18 == 0x27) {
            *pcVar7 = '\\';
            pcVar7 = pcVar7 + 1;
          }
          else {
            uVar11 = uVar11 + 1;
          }
          goto LAB_004017cf;
        default:
          goto switchD_00401948_caseD_2;
        case 0x20:
        case 0x22:
        case 0x24:
LAB_00401859:
          bVar8 = uVar18 != 0 || iVar15 == 0x7f;
          if (uVar11 != 0) {
LAB_00401873:
            pcVar6 = pcVar7 + uVar11;
            pcVar10 = pcVar7;
            do {
              pcVar4 = pcVar10 + 1;
              *pcVar10 = '\\';
              pcVar10 = pcVar4;
              pcVar7 = pcVar6;
            } while (pcVar4 != pcVar6);
          }
          if (bVar8) goto LAB_00401895;
        }
LAB_004017c8:
        *pcVar7 = cVar12;
        pcVar7 = pcVar7 + 1;
        uVar11 = 0;
      }
LAB_004017cf:
      iVar15 = (int)*_Str;
    } while (iVar15 != 0);
    _Str = pcVar7;
    if (uVar11 != 0) {
      _Str = pcVar7 + uVar11;
      do {
        pcVar6 = pcVar7 + 1;
        *pcVar7 = '\\';
        pcVar7 = pcVar6;
      } while (pcVar6 != _Str);
    }
    if ((pcVar16 < _Str) || (iVar17 != 0)) {
      *_Str = '\0';
      *(undefined **)(&stack0xfffffda8 + iVar9) = &stack0xfffffdcc;
      *(undefined4 *)(&stack0xfffffda4 + iVar9) = 0;
      *(uint *)(&stack0xfffffda0 + iVar9) = uVar3;
      *(char **)(&stack0xfffffd9c + iVar9) = pcVar16;
      *(undefined4 *)(&stack0xfffffd98 + iVar9) = 0x401780;
      ___mingw_glob(*(char **)(&stack0xfffffd9c + iVar9),*(uint *)(&stack0xfffffda0 + iVar9),
                    *(undefined4 *)(&stack0xfffffda4 + iVar9),*(char ***)(&stack0xfffffda8 +iVar9))
      ;
    }
  }
  DAT_00408000 = in_stack_fffffdd4;
  __argc = in_stack_fffffdd0;
  return in_stack_fffffdd4;
}


