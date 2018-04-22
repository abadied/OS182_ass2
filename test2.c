#include "types.h"
#include "stat.h"
#include "user.h"

void sig_hand(int);

int
main(int argc, char **argv)
{
  int pid;
  printf(2, "setting signal handler %d\n", signal(5, (sighandler_t)sig_hand));
  if ((pid=fork()) != 0) {
  	printf(2, "son pid: %d\n", pid);
  	sleep(200);
	  printf(2, "TAKE SIGNAL 3 MY SON!!!! %d\n", kill(pid, 3));
    sleep(50);
    printf(2, "STOP MY SON!!!! %d\n", kill(pid, 17));
    sleep(50);
    printf(2, "TAKE SIGNAL 4 MY SON!!!! %d\n", kill(pid, 4));
    printf(2, "TAKE SIGNAL 5 MY SON!!!! %d\n", kill(pid, 5));
    sleep(70);
    printf(2, "CONTINUE MY SON!!!! %d\n", kill(pid, 19));
  	wait();
  	printf(2, "DONE\n");
  }
  else {
    printf(2, "setting signal handler %d\n", signal(3, (sighandler_t)sig_hand));
    printf(2, "setting signal handler %d\n", signal(4, (sighandler_t)sig_hand));
    printf(2, "setting sigmask %d\n", sigprocmask(1<<4));
  	printf(2, "IM THE SON AND MY ID IS %d\n", getpid());
  	for(int i=0 ; i < 10 ; i++) {
  		sleep(50);
  		printf(2, "HEY! IM STILL ALIVE\n");
  	}
  }
  exit();
}

void sig_hand(int signum){
  printf(2, "IM %d AND I GOT SIGNAL %d!!!\n", getpid(), signum);
  return;
}
