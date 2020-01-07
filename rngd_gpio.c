/*
 * Copyright (c) 2020, Rafael R. Sevilla
 * Authors: Rafael R. Sevilla <dido.sevilla@stormwyrm.com>,
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */
#define _GNU_SOURCE

#ifndef HAVE_CONFIG_H
#error Invalid or missing autoconf build environment
#endif

#include "rng-tools-config.h"

#include "rngd.h"
#include "fips.h"
#include "exits.h"
#include "rngd_entsource.h"
#include <wiringPi.h>
#include <time.h>

/* Default RNG data pin */
#define GPIO_DATA_PIN 16
/* Default RNG enable pin */
#define GPIO_EN_PIN 7
/* Default RNG VHIGHSAMPLE pin */
#define GPIO_VL_PIN 1

/* When the EN pin goes high, the VL pin should go to 1 within about this
   many nanoseconds. Nominally it should be within 20 ms, 20,000,000 ns given
   the circuit components used, but it is by default set to 100 ms to be
   safe. */
#define VHIGH_TIMEOUT 100000000L
/* When the EN pin goes low, the VL pin should drop to 0 within about this
   many nanoseconds. Nominally it should be within 12 ms, 12,000,000 ns
   given the circuit components used, but it is by default set to 60 ms
   to be safe. */
#define VLOW_TIMEOUT 60000000L

/* Enable the GPIO random number generator */
static void gpio_enable(struct rng *ent_src)
{
  digitalWrite(ent_src->rng_options[GPIO_OPT_EN_PIN].int_val, 1);
}

/* Disable the GPIO random number generator */
static void gpio_disable(struct rng *ent_src)
{
  digitalWrite(ent_src->rng_options[GPIO_OPT_EN_PIN].int_val, 0);
}

/*
 * Get data from GPIO. This is raw, unfiltered data.
 */
static unsigned int gpio_bytes(struct rng *ent_src, void *ptr,
			       unsigned int count)
{
  unsigned char *cptr = (unsigned char *)ptr;
  int bits;
  unsigned int rcount=0;

  while (count--) {
    for (bits=0; bits<8; bits++) {
      *cptr <<= 1;
      if (digitalRead(ent_src->rng_options[GPIO_OPT_DATA_PIN].int_val))
	*cptr |= 0x01;
      else
	*cptr &= 0xfe;
    }
    cptr++;
    rcount++;
  }
  return(rcount);
}

static int init_gcrypt(const void *key)
{
#ifdef HAVE_LIBGCRYPT
  gcry_error_t gcry_error;

  if (!gcry_check_version(MIN_GCRYPT_VERSION)) {
    message(LOG_DAEMON|LOG_ERR,
	    "libgcrypt version mismatch: have %s, require >= %s\n",
	    gcry_check_version(NULL), MIN_GCRYPT_VERSION);
    return(1);
  }

  gcry_error = gcry_cipher_open(&gcry_cipher_hd, GCRY_CIPHER_AES128,
				GCRY_CIPHER_MODE_CBC, 0);

  if (!gcry_error)
    gcry_error = gcry_cipher_setkey(gcry_cipher_hd, key, AES_BLOCK);

  if (!gcry_error) {
    /*
     * Only need the first 16 bytes of iv_buf. AES-NI can
     * encrypt multiple blocks in parallel but we can't.
     */
    gcry_error = gcry_cipher_setiv(gcry_cipher_hd, iv_buf, AES_BLOCK);
  }

  if (gcry_error) {
    message(LOG_DAEMON|LOG_ERR,
	    "could not set key or IV: %s\n",
	    gcry_strerror(gcry_error));
    gcry_cipher_close(gcry_cipher_hd);
    return(1);
  }
  return(0);
#else
  (void)key;
  return(1);
#endif
}


int validate_gpio_options(struct rng *ent_src)
{
  int pin = ent_src->rng_options[GPIO_OPT_DATA_PIN].int_val;
  int en = ent_src->rng_options[GPIO_OPT_EN_PIN].int_val;
  int vnlevel = ent_src->rng_options[GPIO_OPT_VL_PIN].int_val;

  if (!pin) {
    message(LOG_DAEMON|LOG_WARNING, "GPIORNG requires a data pin number, setting pin number to %d", GPIO_DATA_PIN);
    ent_src->rng_options[GPIO_OPT_DATA_PIN].int_val = GPIO_DATA_PIN;
  }

  if (!en) {
    message(LOG_DAEMON|LOG_WARNING, "GPIORNG requires an enable pin number, setting pin number to %d", GPIO_EN_PIN);
    ent_src->rng_options[GPIO_OPT_EN_PIN].int_val = GPIO_EN_PIN;
  }

  if (!vnlevel) {
    message(LOG_DAEMON|LOG_WARNING, "GPIORNG requires an voltage level pin number, setting pin number to %d", GPIO_VL_PIN);
    ent_src->rng_options[GPIO_OPT_VL_PIN].int_val = GPIO_VL_PIN;
  }
  return(0);
}

static struct timespec timer_start()
{
  struct timespec start_time;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_time);
  return(start_time);
}

static long timer_end(struct timespec start_time)
{
  struct timespec end_time;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_time);
  long diffInNanos = (end_time.tv_sec - start_time.tv_sec) * 1000000000L + (end_time.tv_nsec - start_time.tv_nsec);
  return(diffInNanos);
}

int init_gpiorng_entropy_source(struct rng *ent_src)
{
  int pin = ent_src->rng_options[GPIO_OPT_DATA_PIN].int_val;
  int en = ent_src->rng_options[GPIO_OPT_EN_PIN].int_val;
  int vnlevel = ent_src->rng_options[GPIO_OPT_VL_PIN].int_val;
  struct timespec tm;

  wiringPiSetup();
  pinMode(pin, INPUT);
  pinMode(en, OUTPUT);
  pinMode(vnlevel, INPUT);

  /* Boost converter test:
     Try to enable the RNG, and check to see if the voltage
     level pin goes up promptly to at least 18Vdc (1) when it is
     enabled. */
  gpio_enable(ent_src);
  tm = timer_start();
  while (digitalRead(vnlevel) == 0) {
    if (timer_end(tm) > VHIGH_TIMEOUT) {
      message(LOG_DAEMON|LOG_ERR, "GPIO rng fails, voltage level not increasing");
      return(1);
    }
  }

  /* Try to disable the RNG, and then see how long it will take for the
     voltage level pin to drop to 0 (below 12Vdc). */
  tm = timer_start();
  gpio_disable(ent_src);
  while (digitalRead(vnlevel) == 1) {
    if (timer_end(tm) > VLOW_TIMEOUT) {
      message(LOG_DAEMON|LOG_ERR, "GPIO rng fails, voltage level not decreasing in time");
      return(1);
    }
  }
  long vlow_time = timer_end(tm);
  message(LOG_DAEMON|LOG_DEBUG, "GPIO rng: %ld ns to discharge", vlow_time);
  message(LOG_DAEMON|LOG_INFO, "Enabling GPIO rng support\n");
}

extern void close_gpiorng_entropy_source(struct rng *ent_src)
{
  gpio_disable(ent_src);
}

int xread_gpiorng(void *buf, size_t size, struct rng *ent_src)
{
}
