#ifndef _EXPORTER_H
#define _EXPORTER_H

#include <prometheus/exposer.h>
#include <prometheus/histogram.h>
#include <prometheus/registry.h>

#include "../utils/log.hpp"
#include <map>
#include <sstream>

void run_exporter();

#endif