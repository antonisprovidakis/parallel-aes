/**
 * Energy reading for an ODROID with INA231 power sensors, using ioctl on
 * device files instead of sysfs.
 *
 * @author Connor Imes
 * @date 2015-10-14
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "energymon.h"
#include "energymon-odroid-ioctl.h"
#include "energymon-time-util.h"
#include "energymon-util.h"

#ifdef ENERGYMON_DEFAULT
#include "energymon-default.h"

int energymon_get_default(energymon *em)
{
  return energymon_get_odroid_ioctl(em);
}
#endif

#define SENSOR_POLL_DELAY_US_DEFAULT 263808// 500000 //263808
#define SENSOR_COUNT 4

#define INA231_IOCGREG _IOR('i', 1, ina231_iocreg_t *)
#define INA231_IOCSSTATUS _IOW('i', 2, ina231_iocreg_t *)
#define INA231_IOCGSTATUS _IOR('i', 3, ina231_iocreg_t *)

/**
 * This struct is defined in the kernel: drivers/hardkernel/ina231-misc.h
 * See the branches in HardKernel's fork.
 */
typedef struct ina231_iocreg
{
  char name[20];
  unsigned int enable;
  unsigned int cur_uV;
  unsigned int cur_uA;
  unsigned int cur_uW;
} ina231_iocreg_t;

typedef struct ina231_sensor
{
  int fd;
  ina231_iocreg_t data;
} ina231_sensor_t;

static const char *dev_sensor[] = {
    "/dev/sensor_arm", // BIG cluster
    "/dev/sensor_kfc", // LITTLE cluster
    "/dev/sensor_mem", // MEM
    "/dev/sensor_g3d"  // GPU
};

typedef struct energymon_odroid_ioctl
{
  // sensors
  ina231_sensor_t sensor[SENSOR_COUNT];
  // sensor update interval in microseconds
  unsigned long poll_delay_us;
  // total energy estimate
  uint64_t total_uj;
  // thread variables
  pthread_t thread;
  int poll_sensors;
} energymon_odroid_ioctl;

static inline int set_sensor_enable(ina231_sensor_t *sensor, int enable)
{
  sensor->data.enable = enable ? 1 : 0;
  return ioctl(sensor->fd, INA231_IOCSSTATUS, &sensor->data) < 0;
}

static inline int read_sensor_status(ina231_sensor_t *sensor)
{
  return ioctl(sensor->fd, INA231_IOCGSTATUS, &sensor->data) < 0;
}

static inline int read_sensor_data(ina231_sensor_t *sensor)
{
  return ioctl(sensor->fd, INA231_IOCGREG, &sensor->data) < 0;
}

// static inline void get_sensors_data(FILE *f, ina231_sensor_t sensors[], sensors_data_t *data)
// {
/*
  data->armuV = (float)(sensors[0].data.cur_uV / 100000) / 10;
  data->armuA = (float)(sensors[0].data.cur_uA / 1000) / 1000;
  data->armuW = (float)(sensors[0].data.cur_uW / 1000) / 1000;
  fprintf(f,"%.3f\t", data->armuV);
  fprintf(f,"%.3f\t", data->armuA);
  fprintf(f,"%.3f\t", data->armuW);

  data->kfcuV = (float)(sensors[1].data.cur_uV / 100000) / 10;
  data->kfcuA = (float)(sensors[1].data.cur_uA / 1000) / 1000;
  data->kfcuW = (float)(sensors[1].data.cur_uW / 1000) / 1000;
  fprintf(f,"%.3f\t", data->kfcuV);
  fprintf(f,"%.3f\t", data->kfcuA);
  fprintf(f,"%.3f\t", data->kfcuW);

  data->memuV = (float)(sensors[2].data.cur_uV / 100000) / 10;
  data->memuA = (float)(sensors[2].data.cur_uA / 1000) / 1000;
  data->memuW = (float)(sensors[2].data.cur_uW / 1000) / 1000;
  fprintf(f,"%.3f\t", data->memuV);
  fprintf(f,"%.3f\t", data->memuA);
  fprintf(f,"%.3f\t", data->memuW);

  data->g3duV = (float)(sensors[3].data.cur_uV / 100000) / 10;
  data->g3duA = (float)(sensors[3].data.cur_uA / 1000) / 1000;
  data->g3duW = (float)(sensors[3].data.cur_uW / 1000) / 1000;
  fprintf(f,"%.3f\t", data->g3duV);
  fprintf(f,"%.3f\t", data->g3duA);
  fprintf(f,"%.3f\t", data->g3duW); 
  fprintf(f,"\n"); 
*/
//  printf("kfcuW: %.3f\n\n", data->kfcuW);

/*puts("Sensors Dataset: \n");
  printf("A15 \n");
  data->armuV = (float)(sensors[0].data.cur_uV / 100000) / 10;
  data->armuA = (float)(sensors[0].data.cur_uA / 1000) / 1000;
  data->armuW = (float)(sensors[0].data.cur_uW / 1000) / 1000;
  printf("armuV: %.3f\n", data->armuV);
  printf("armuA: %.3f\n", data->armuA);
  printf("armuW: %.3f\n\n", data->armuW);

  printf("A7 \n");
  data->kfcuV = (float)(sensors[1].data.cur_uV / 100000) / 10;
  data->kfcuA = (float)(sensors[1].data.cur_uA / 1000) / 1000;
  data->kfcuW = (float)(sensors[1].data.cur_uW / 1000) / 1000;
  printf("kfcuV: %.3f\n", data->kfcuV);
  printf("kfcuA: %.3f\n", data->kfcuA);
  printf("kfcuW: %.3f\n\n", data->kfcuW);

  printf("MEM \n");
  data->memuV = (float)(sensors[2].data.cur_uV / 100000) / 10;
  data->memuA = (float)(sensors[2].data.cur_uA / 1000) / 1000;
  data->memuW = (float)(sensors[2].data.cur_uW / 1000) / 1000;
  printf("memuV: %.3f\n", data->memuV);
  printf("memuA: %.3f\n", data->memuA);
  printf("memuW: %.3f\n\n", data->memuW);

  printf("GPU \n");
  data->g3duV = (float)(sensors[3].data.cur_uV / 100000) / 10;
  data->g3duA = (float)(sensors[3].data.cur_uA / 1000) / 1000;
  data->g3duW = (float)(sensors[3].data.cur_uW / 1000) / 1000;
  printf("g3duV: %.3f\n", data->g3duV);
  printf("g3duA: %.3f\n", data->g3duA);
  printf("g3duW: %.3f\n\n", data->g3duW);
*/
// }

/**
 * Close all the sensor device files.
 * If ODROID_IOCTL_DISABLE_ON_CLOSE is defined, the sensors will be stopped.
 */
static inline int close_all_sensors(energymon_odroid_ioctl *em)
{
  int ret = 0;
  unsigned int i;
  for (i = 0; i < SENSOR_COUNT; i++)
  {
#ifdef ODROID_IOCTL_DISABLE_ON_CLOSE
    if (em->sensor[i].fd > 0 &&
        em->sensor[i].data.enable && set_sensor_enable(&em->sensor[i], 0))
    {
      perror(em->sensor[i].data.name);
      ret = -1;
    }
#endif
    if (em->sensor[i].fd > 0 && close(em->sensor[i].fd))
    {
      perror(dev_sensor[i]);
      ret = -1;
    }
  }
  return ret;
}

/**
 * Open all the sensor device files, check their status, and enable them.
 */
static inline int open_all_sensors(energymon_odroid_ioctl *em)
{
  unsigned int i;
  for (i = 0; i < SENSOR_COUNT; i++)
  {
    if ((em->sensor[i].fd = open(dev_sensor[i], O_RDWR)) <= 0 ||
        read_sensor_status(&em->sensor[i]) ||
        (!em->sensor[i].data.enable && set_sensor_enable(&em->sensor[i], 1)))
    {
      perror(dev_sensor[i]);
      return -1;
    }
  }
  return 0;
}

int energymon_finish_odroid_ioctl(energymon *em)
{
  if (em == NULL || em->state == NULL)
  {
    errno = EINVAL;
    return -1;
  }

  int err_save = 0;
  energymon_odroid_ioctl *state = (energymon_odroid_ioctl *)em->state;
  if (state->poll_sensors)
  {
    // stop sensors polling thread and cleanup
    state->poll_sensors = 0;
#ifndef __ANDROID__
    pthread_cancel(state->thread);
#endif
    err_save = pthread_join(state->thread, NULL);
  }
  if (close_all_sensors(state))
  {
    err_save = err_save ? err_save : errno;
  }
  free(em->state);
  em->state = NULL;
  errno = err_save;
  return errno ? -1 : 0;
}

/**
 * pthread function to poll the sensors at regular intervals.
 */
static void *odroid_ioctl_poll_sensors(void *args)
{
  // puts("-- Poll data from sensors.");
  // puts("-- Create a Datalog file.");

  energymon_odroid_ioctl *state = (energymon_odroid_ioctl *)args;
  uint64_t sum_uw;
  unsigned int i;
  int64_t exec_us;
  int err_save;
  struct timespec ts;
  // FILE *f;

  // sensors_data_t sensors_data;

  if (energymon_clock_gettime(&ts))
  {
    // must be that CLOCK_MONOTONIC is not supported
    perror("odroid_ioctl_poll_sensors");
    return (void *)NULL;
  }

  // f = fopen("datalog.log", "a");

  energymon_sleep_us(state->poll_delay_us, &state->poll_sensors);
  while (state->poll_sensors)
  {
    //puts("In while of thread\n");

    // read individual sensors
    for (errno = 0, sum_uw = 0, i = 0; i < SENSOR_COUNT && !errno; i++)
    {
      if (!read_sensor_data(&state->sensor[i]))
      {
        sum_uw += state->sensor[i].data.cur_uW;
      }
    }
    err_save = errno;

    // get_sensors_data(f, state->sensor, &sensors_data);

    exec_us = energymon_gettime_us(&ts);
    if (err_save)
    {
      errno = err_save;
      perror("odroid_ioctl_poll_sensors: skipping power sensor reading");
    }
    else
    {
      state->total_uj += sum_uw * exec_us / 1000000;
    }
    // sleep for the update interval of the sensors (minus most overhead)
    energymon_sleep_us(2 * state->poll_delay_us - exec_us, &state->poll_sensors);
    errno = 0;
  }

  // fclose(f);

  return (void *)NULL;
}

/**
 * Open all sensor files and start the thread to poll the sensors.
 */
int energymon_init_odroid_ioctl(energymon *em)
{
  //printf("in energymon_init_odroid_ioctl\n");

  if (em == NULL || em->state != NULL)
  {
    errno = EINVAL;
    return -1;
  }

  int err_save;
  energymon_odroid_ioctl *state = calloc(1, sizeof(energymon_odroid_ioctl));
  if (state == NULL)
  {
    return -1;
  }

  // TODO: determine at runtime
  state->poll_delay_us = SENSOR_POLL_DELAY_US_DEFAULT;

  // open and enable the sensors
  if (open_all_sensors(state))
  {
    close_all_sensors(state);
    free(state);
    return -1;
  }

  // start sensors polling thread
  state->poll_sensors = 1;
  errno = pthread_create(&state->thread, NULL, odroid_ioctl_poll_sensors, state);

  //printf("in energymon_init_odroid_ioctl   3\n");

  if (errno)
  {
    err_save = errno;
    close_all_sensors(state);
    free(state);
    errno = err_save;
    return -1;
  }

  em->state = state;
  return 0;
}

uint64_t energymon_read_total_odroid_ioctl(const energymon *em)
{
  if (em == NULL || em->state == NULL)
  {
    errno = EINVAL;
    return 0;
  }
  return ((energymon_odroid_ioctl *)em->state)->total_uj;
}

char *energymon_get_source_odroid_ioctl(char *buffer, size_t n)
{
  return energymon_strencpy(buffer, "ODROID INA231 Power Sensors via ioctl", n);
}

uint64_t energymon_get_interval_odroid_ioctl(const energymon *em)
{
  if (em == NULL || em->state == NULL)
  {
    errno = EINVAL;
    return 0;
  }
  return ((energymon_odroid_ioctl *)em->state)->poll_delay_us;
}

uint64_t energymon_get_precision_odroid_ioctl(const energymon *em)
{
  if (em == NULL || em->state == NULL)
  {
    errno = EINVAL;
    return 0;
  }
  // microwatts at refresh interval
  uint64_t prec = energymon_get_interval_odroid_ioctl(em) / 1000000;
  return prec ? prec : 1;
}

int energymon_is_exclusive_odroid_ioctl(void)
{
  return 0;
}

int energymon_get_odroid_ioctl(energymon *em)
{
  //printf("INIT of energymon\n");
  if (em == NULL)
  {
    errno = EINVAL;
    return -1;
  }
  em->finit = &energymon_init_odroid_ioctl;
  em->fread = &energymon_read_total_odroid_ioctl;
  em->ffinish = &energymon_finish_odroid_ioctl;
  em->fsource = &energymon_get_source_odroid_ioctl;
  em->finterval = &energymon_get_interval_odroid_ioctl;
  em->fprecision = &energymon_get_precision_odroid_ioctl;
  em->fexclusive = &energymon_is_exclusive_odroid_ioctl;
  em->state = NULL;
  return 0;
}
