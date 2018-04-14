#include "types.h"
#include "stat.h"
#include "user.h"


int
main(int argc, char **argv)
{
  int pid;
  if ((pid=fork()) != 0) {
  	printf(2, "son pid: %d\n", pid);
  	sleep(200);
	  printf(2, "STOPPING MY SON!!!! %d\n", kill(pid, 5));
    sleep(200);
    printf(2, "WAKE UP MY SON!!!! I AM YOUR FATHER!!!!!!! %d\n", kill(pid, 19));
  	wait();
  	printf(2, "DONE\n");
  }
  else {
    // signal(5, (sighandler_t)1);
  	printf(2, "IM THE SON AND MY ID IS %d\n", getpid());
  	for(int i=0 ; i < 10 ; i++) {
  		sleep(50);
  		printf(2, "HEY! IM STILL ALIVE\n");
  	}
  }
  exit();
}
