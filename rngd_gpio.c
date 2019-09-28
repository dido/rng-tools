/*
 * Copyright (c) 2019, Rafael R. Sevilla
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

int validate_gpio_options(struct rng *ent_src)
{
  int pin = ent_src->rng_options[GPIO_OPT_PIN].int_val;
  int vnlevel = ent_src->rng_options[GPIO_OPT_VNLEVEL].int_val;

  if (!pin) {
    message(LOG_DAEMON|LOG_ERR, "GPIORNG requires a pin number, setting pin number to 15");
    ent_src->rng_options[GPIO_OPT_PIN].int_val = 15;
  }
}

int init_gpiorng_entropy_source(struct rng *ent_src)
{
  wiringPiSetup();
}

extern void close_gpiorng_entropy_source(struct rng *)
{
}


int xread_gpiorng(void *buf, size_t size, struct rng *ent_src)
{
}
