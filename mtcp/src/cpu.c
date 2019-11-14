#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <numa.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <assert.h>
#include "mtcp_api.h"

#define MAX_FILE_NAME 1024

/*----------------------------------------------------------------------------*/
int 
GetNumCPUs() 
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}
/*----------------------------------------------------------------------------*/
pid_t 
Gettid()
{
	return syscall(__NR_gettid);
}
/*----------------------------------------------------------------------------*/
int 
mtcp_core_affinitize(int cpu)
{
	cpu_set_t cpus;
	struct bitmask *bmask;
	FILE *fp;
	char sysfname[MAX_FILE_NAME];
	int phy_id;
	size_t n;
	int ret;
	int unused;

	n = GetNumCPUs();

	if (cpu < 0 || cpu >= (int) n) {
		errno = -EINVAL;
		return -1;
	}

	CPU_ZERO(&cpus);
	CPU_SET((unsigned)cpu, &cpus);

	ret = sched_setaffinity(Gettid(), sizeof(cpus), &cpus);

	if (numa_max_node() == 0)
		return ret;

	bmask = numa_bitmask_alloc(numa_max_node() + 1);
	assert(bmask);

	/* read physical id of the core from sys information */
	snprintf(sysfname, MAX_FILE_NAME - 1, 
			"/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
	fp = fopen(sysfname, "r");
	if (!fp) {
		perror(sysfname);
		errno = EFAULT;
		return -1;
	}
	ret = fscanf(fp, "%d", &phy_id);
	if (ret != 1) {
		fclose(fp);
		perror("Fail to read core id");
		errno = EFAULT;
		return -1;
	}

	numa_bitmask_setbit(bmask, phy_id);
	numa_set_membind(bmask);
	numa_bitmask_free(bmask);

	fclose(fp);

	UNUSED(unused);
	return ret;
}
