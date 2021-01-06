
void win_function1(void)

{
  win1 = 1;
  return;
}

void win_function2(int param_1)

{
  if ((win1 == '\0') || (param_1 != -0x45555553)) {
    if (win1 == '\0') {
      puts("Nope. Try a little bit harder.");
    }
    else {
      puts("Wrong Argument. Try Again.");
    }
  }
  else {
    win2 = 1;
  }
  return;
}



void flag(int param_1)

{
  char local_40 [48];
  FILE *local_10;
  
  local_10 = fopen("flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    puts(
        "Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are runningthis on the shell server."
        );
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  fgets(local_40,0x30,local_10);
  if (((win1 == '\0') || (win2 == '\0')) || (param_1 != -0x21524553	)) {
    if ((win1 == '\0') || (win2 == '\0')) {
      if ((win1 == '\0') && (win2 == '\0')) {
        puts("You won\'t get the flag that easy..");
      }
      else {
        puts("Nice Try! You\'re Getting There!");
      }
    }
    else {
      puts(
          "Incorrect Argument. Remember, you can call other functions in between each win function!"
          );
    }
  }
  else {
    printf("%s",local_40);
  }
  return;
}


void vuln(void)

{
  char local_1c [24];
  
  printf("Enter your input> ");
  gets(local_1c);
  return;
}

undefined4 main(void)

{
  __gid_t __rgid;
  
  setvbuf(stdout,(char *)0x0,2,0);
  __rgid = getegid();
  setresgid(__rgid,__rgid,__rgid);
  vuln();
  return 0;
}
