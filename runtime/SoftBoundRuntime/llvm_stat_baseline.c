#ifdef __SOFTBOUNDCETS_STATISTICS_MODE

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>


static __attribute__ ((__destructor__))
void __softboundcets_statistics_fini() {

  // 4kB page size, 1024*1024 bytes per MB,
  const double MULTIPLIER = 4096.0/(1024.0*1024.0); 
  FILE* proc_file, *statistics_file;
  size_t total_size_in_pages = 0;
  size_t res_size_in_pages = 0;

  statistics_file = fopen("bench_statistics.log", "w");
  assert(statistics_file != NULL);

  proc_file = fopen("/proc/self/statm", "r");
  fscanf(proc_file, "%zd %zd", &total_size_in_pages, &res_size_in_pages);

  fprintf(statistics_file, "memory_total: %lf \n", total_size_in_pages*MULTIPLIER);
  fprintf(statistics_file, "memory_resident: %lf \n", res_size_in_pages*MULTIPLIER);

  fprintf(statistics_file, 
          "============================================\n");
  fclose(statistics_file);
  
}

#endif
