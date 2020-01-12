/*
 * Copyright (c) 2020 Rafael R. Sevilla
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
#include <math.h>
#include <fcntl.h>
#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif
 
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

/* Number of times to repeat self-test */
#define SELFTEST_COUNT 16

/* Threshold for entropy. If entropy is below this level, we consider the RNG
   circuit failed. */
#define ENT_THRESHOLD 0.6

#ifdef HAVE_LIBGCRYPT

#define MIN_GCRYPT_VERSION "1.0.0"

#define AES_BLOCK 16
#define CHUNK_SIZE (AES_BLOCK*8)
#define RDRAND_ROUNDS 512

static unsigned char iv_buf[CHUNK_SIZE] __attribute__((aligned(128)));
static gcry_cipher_hd_t gcry_cipher_hd;

#endif

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

/* Enable GPIO random number generator, and wait for it to become active
   by monitoring VL pin */
static int gpio_enable(struct rng *ent_src)
{
  struct timespec tm;

  digitalWrite(ent_src->rng_options[GPIO_OPT_EN_PIN].int_val, 1);
  tm = timer_start();
  while (digitalRead(ent_src->rng_options[GPIO_OPT_VL_PIN].int_val) == 0) {
    if (timer_end(tm) > VHIGH_TIMEOUT) {
      message(LOG_DAEMON|LOG_ERR, "GPIO rng fails, voltage level not increasing");
      return(0);
    }
  }
  return(1);
}

/* Disable the GPIO random number generator by shutting down enable pin */
static void gpio_disable(struct rng *ent_src)
{
  digitalWrite(ent_src->rng_options[GPIO_OPT_EN_PIN].int_val, 0);
}

static long ccount[2], totalc;
static double ent, prob;

/* Read a bit from the GPIO pin */
static int gpio_bit(struct rng *ent_src)
{
  int bit = digitalRead(ent_src->rng_options[GPIO_OPT_DATA_PIN].int_val);
  if (totalc >= CHUNK_SIZE * RDRAND_ROUNDS * 1024) {
    ent = 0.0;
    if (ccount[0] > 0 && ccount[1] > 0) {
      prob = ((double)ccount[0])/((double)totalc);
      ent += prob * log2(1.0/prob);
      prob = ((double)ccount[1])/((double)totalc);
      ent += prob * log2(1.0/prob);
    }
    message(LOG_DAEMON|LOG_DEBUG, "GPIO entropy = %g shannon\n", ent);
    ccount[0] = ccount[1] = totalc = 0;
  }
  ccount[bit]++;
  totalc++;
  return(bit);
}

/*
 * Get data from GPIO
 */
static int gpio_bytes_raw(struct rng *ent_src, void *ptr, size_t count)
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

/* Von Neumann whitening. Used when AES/libgcrypt is disabled. We might want
   to consider other algorithms to do this in the future. */
static int gpio_vnbytes(struct rng *ent_src, void *ptr, size_t count)
{
  unsigned char *cptr = (unsigned char *)ptr;
  int bits, bit1, bit2;
  unsigned int rcount=0, repetitions;

  if (!gpio_enable(ent_src))
    return(1);
  while (count--) {
    for (bits=0; bits<8; bits++) {
      *cptr <<= 1;
      repetitions = 0;
      do {
	bit1 = gpio_bit(ent_src);
	bit2 = gpio_bit(ent_src);
	if (repetitions++ > 1024) {
	  message(LOG_DAEMON|LOG_ERR, "von Neumann whitening exceeded max iterations");
	  return(1);
	}
      } while (bit1 == bit2);
      if (bit1)
	*cptr |= 0x01;
      else
	*cptr &= 0xfe;
    }
    cptr++;
    rcount++;
  }
  gpio_disable(ent_src);
  return(0);
}

#ifdef HAVE_LIBGCRYPT

static unsigned int gpio_bytes(struct rng *ent_src, void *ptr, size_t count)
{
  unsigned char *cptr = (unsigned char *)ptr;
  int bits;
  unsigned int rcount=0;

  while (count--) {
    for (bits=0; bits<8; bits++) {
      *cptr <<= 1;
      if (gpio_bit(ent_src))
	*cptr |= 0x01;
      else
	*cptr &= 0xfe;
    }
    cptr++;
    rcount++;
  }
  return(rcount);
}

static inline int gcrypt_mangle(unsigned char *tmp)
{
#ifdef HAVE_LIBGCRYPT
  gcry_error_t gcry_error;

  /* Encrypt tmp in-place. */
  gcry_error = gcry_cipher_encrypt(gcry_cipher_hd, tmp,
				   AES_BLOCK * RDRAND_ROUNDS,
				   NULL, 0);

  if (gcry_error) {
    message(LOG_DAEMON|LOG_ERR,
	    "gcry_cipher_encrypt error: %s\n",
	    gcry_strerror(gcry_error));
    return -1;
  }
  return 0;
#else
  (void)tmp;
  return -1;
#endif
}

/* Use gcrypt to whiten the output of the GPIO */
static int gpio_gbytes(struct rng *ent_src, void *buf, size_t size)
{
  static unsigned char rdrand_buf[CHUNK_SIZE*RDRAND_ROUNDS];
  static unsigned int rdrand_bytes = 0;
  char *p = buf;
  size_t chunk;
  unsigned char *rdrand_ptr, *data;
  unsigned int rand_bytes;

  if (!gpio_enable(ent_src))
    return(1);
  while (size) {
    rand_bytes = AES_BLOCK * RDRAND_ROUNDS - rdrand_bytes;
    if (rand_bytes) {
      rdrand_ptr = rdrand_buf + rdrand_bytes;
      rand_bytes = gpio_bytes(ent_src, rdrand_ptr, rand_bytes);
      rdrand_bytes += rand_bytes;
      continue;
    }
    /* full rdrand_buf */
    if (!gcrypt_mangle(rdrand_buf)) {
      data = rdrand_buf + AES_BLOCK * (RDRAND_ROUNDS - 1);
      chunk = AES_BLOCK;
    } else {
      gpio_disable(ent_src);
      return(1);
    }
    rdrand_bytes = 0;
    chunk = (chunk > size) ? size : chunk;
    memcpy(p, data, chunk);
    p += chunk;
    size -= chunk;
  }
  gpio_disable(ent_src);
  return(0);
}

#endif


static int init_gcrypt(struct rng *ent_src)
{
#ifdef HAVE_LIBGCRYPT
  gcry_error_t gcry_error;
  unsigned char xkey[AES_BLOCK];	/* Material to XOR into the key */
  /* AES data reduction key */
  static unsigned char key[AES_BLOCK] =
    { 0x00,0x10,0x20,0x30,0x40,0x50,0x60,0x70,
      0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0 };
  int fd, i;

  if (!gcry_check_version(MIN_GCRYPT_VERSION)) {
    message(LOG_DAEMON|LOG_ERR,
	    "libgcrypt version mismatch: have %s, require >= %s\n",
	    gcry_check_version(NULL), MIN_GCRYPT_VERSION);
    return(1);
  }

  if (gpio_bytes(ent_src, xkey, sizeof(xkey)) != sizeof(xkey))
    return(1);

  fd = open("/dev/urandom", O_RDONLY);
  if (fd >= 0) {
    read(fd, key, sizeof key);
    close(fd);
  }

  if (gpio_bytes(ent_src, iv_buf, CHUNK_SIZE) != CHUNK_SIZE)
    return(1);

  for (i=0; i<(int)sizeof(key); i++)
    key[i] ^= xkey[i];

  gcry_error = gcry_cipher_open(&gcry_cipher_hd, GCRY_CIPHER_AES128,
				GCRY_CIPHER_MODE_CBC, 0);

  if (!gcry_error)
    gcry_error = gcry_cipher_setkey(gcry_cipher_hd, key, AES_BLOCK);

  if (!gcry_error)
    gcry_error = gcry_cipher_setiv(gcry_cipher_hd, iv_buf, AES_BLOCK);
  
  if (gcry_error) {
    message(LOG_DAEMON|LOG_ERR,
	    "could not initialise gcrypt: %s\n",
	    gcry_strerror(gcry_error));
    gcry_cipher_close(gcry_cipher_hd);
    return(1);
  }
  return(0);
#else
  (void)ent_src;
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

int init_gpiorng_entropy_source(struct rng *ent_src)
{
  int pin = ent_src->rng_options[GPIO_OPT_DATA_PIN].int_val;
  int en = ent_src->rng_options[GPIO_OPT_EN_PIN].int_val;
  int vnlevel = ent_src->rng_options[GPIO_OPT_VL_PIN].int_val;
  int i, j, c;
  struct timespec tm;
  unsigned char buf[64];

  wiringPiSetup();
  pinMode(pin, INPUT);
  pinMode(en, OUTPUT);
  pinMode(vnlevel, INPUT);

  /* Boost converter test:
     Try to enable the RNG, and check to see if the voltage
     level pin goes up promptly to at least 18Vdc (1) when it is
     enabled. */
  if (!gpio_enable(ent_src))
    return(1);

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

  /* Try to do some basic entropy estimation of the raw RNG stream to make sure
     it hasn't failed in some fundamental way. */
  ccount[0] = ccount[1] = totalc = 0;
  ent = 0.0;
  /* Repeat self-test raw read SELFTEST_COUNT times, more repetitions
     give more accurate estimates of GPIO rng entropy */
  for (j=0; j<SELFTEST_COUNT; j++) {
    /* Enable */
    if (!gpio_enable(ent_src)) {
      return(1);
    }
    /* read raw data from GPIO RNG */
    gpio_bytes(ent_src, buf, sizeof(buf)/sizeof(unsigned char));
    gpio_disable(ent_src);

    /* Calculate counts of 0/1 bits */
    for (i=0; i<sizeof(buf)/sizeof(unsigned char); i++) {
      /* Brian W. Kernighan's Hamming weight / popcount algorithm */
      for (c=0; buf[i]; c++)
	buf[i] &= buf[i] - 1;
      ccount[1] += c;
      ccount[0] += 8-c;
      totalc += 8;
    }
  }
  /* Calculate entropy based on bit counts */
  ent = 0.0;
  /* If either bin is 0 then entropy is zero, and the RNG is clearly failed */
  if (ccount[0] <= 0 || ccount[1] <= 0)  {
    message(LOG_DAEMON|LOG_ERR, "GPIO rng fails, entropy is zero\n");
    return(1);
  }

  /* Calculate probabilities of 0 or 1 */
  prob = ((double)ccount[0])/((double)totalc);
  ent += prob * log2(1.0/prob);
  prob = ((double)ccount[1])/((double)totalc);
  ent += prob * log2(1.0/prob);
  message(LOG_DAEMON|LOG_DEBUG, "GPIO entropy = %g shannon\n", ent);

  if (ent < ENT_THRESHOLD) {
    message(LOG_DAEMON|LOG_ERR, "GPIO rng fails, entropy is below threshold\n");
    return(1);
  }
  ccount[0] = ccount[1] = totalc = 0;

  if (ent_src->rng_options[GPIO_OPT_AES].int_val && init_gcrypt(ent_src)) {
    ent_src->rng_options[GPIO_OPT_AES].int_val = 0;
    message(LOG_DAEMON|LOG_WARNING, "No AES whitening method available for GPIO\n");
  }

  message(LOG_DAEMON|LOG_INFO, "Enabling GPIO rng support\n");
  return(0);
}

extern void close_gpiorng_entropy_source(struct rng *ent_src)
{
  gpio_disable(ent_src);
}

int xread_gpiorng(void *buf, size_t size, struct rng *ent_src)
{
  /* If AES is disabled or not present, use von Neumann whitening */
  if (!ent_src->rng_options[GPIO_OPT_AES].int_val) {    
    return(gpio_vnbytes(ent_src, buf, size));
  }
#ifdef HAVE_LIBGCRYPT
  return(gpio_gbytes(ent_src, buf, size));
#else
  return(gpio_vnbytes(ent_src, buf, size));
#endif
}
