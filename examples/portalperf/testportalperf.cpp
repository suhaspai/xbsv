// Copyright (c) 2014 Quanta Research Cambridge, Inc.

// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "PortalPerfIndicationWrapper.h"
#include "PortalPerfRequestProxy.h"
#include "GeneratedTypes.h"

//#define DEBUG 1

#ifdef DEBUG
#define DEBUGWHERE() \
  fprintf(stderr, "at %s, %s:%d\n", __FUNCTION__, __FILE__, __LINE__)
#else
#define DEBUGWHERE()
#endif

#define LOOP_COUNT 10000

PortalPerfRequestProxy *portalPerfRequestProxy = 0;

int heard_count;

static void *wait_for(int n)
{
    void *rc = NULL;
    while ((heard_count != n) && !rc) {
        rc = portalExec_poll(0);
        if ((long)rc >= 0)
            rc = portalExec_event();
    }
    return rc;
}

uint32_t vrl1, vrl2, vrl3, vrl4;
uint64_t vrd1, vrd2, vrd3, vrd4;

class PortalPerfIndication : public PortalPerfIndicationWrapper
{
public:
  virtual void spit() {
	DEBUGWHERE();
	heard_count++;
    }
  virtual void spitl(uint32_t v1) {
	DEBUGWHERE();
	heard_count++;
	vrl1 = v1;
    }
  virtual void spitll(uint32_t v1, uint32_t v2) {
	DEBUGWHERE();
        heard_count++;
	vrl1 = v1;
	vrl2 = v2;
    }
  virtual void spitlll(uint32_t v1, uint32_t v2, uint32_t v3) {
	DEBUGWHERE();
        heard_count++;
	vrl1 = v1;
	vrl2 = v2;
	vrl3 = v3;
    }
  virtual void spitllll(uint32_t v1, uint32_t v2, uint32_t v3, uint32_t v4) {
	DEBUGWHERE();
        heard_count++;
	vrl1 = v1;
	vrl2 = v2;
	vrl3 = v3;
	vrl4 = v4;
    }
  virtual void spitd(uint64_t v1) {
	DEBUGWHERE();
        heard_count++;
	vrd1 = v1;
    }
  virtual void spitdd(uint64_t v1, uint64_t v2) {
	DEBUGWHERE();
        heard_count++;
	vrd1 = v1;
	vrd2 = v2;
    }
  virtual void spitddd(uint64_t v1, uint64_t v2, uint64_t v3) {
	DEBUGWHERE();
        heard_count++;
	vrd1 = v1;
	vrd2 = v2;
	vrd3 = v3;
    }
  virtual void spitdddd(uint64_t v1, uint64_t v2, uint64_t v3, uint64_t v4) {
	DEBUGWHERE();
        heard_count++;
	vrd1 = v1;
	vrd2 = v2;
	vrd3 = v3;
	vrd4 = v4;
    }
    PortalPerfIndication(unsigned int id) : PortalPerfIndicationWrapper(id) {}
};

uint32_t vl1, vl2, vl3, vl4;
uint64_t vd1, vd2, vd3, vd4;

void call_swallow(void)
{
  DEBUGWHERE();
  start_timer(0);
  catch_timer(0);
  portalPerfRequestProxy->swallow();
  catch_timer(19);
}

void call_swallowl(void)
{
  DEBUGWHERE();
  start_timer(0);
  catch_timer(0);
  portalPerfRequestProxy->swallowl(vl1);
  catch_timer(19);
}

void call_swallowll(void)
{
  DEBUGWHERE();
  start_timer(0);
  catch_timer(0);
  portalPerfRequestProxy->swallowll(vl1, vl2);
  catch_timer(19);
}

void call_swallowlll(void)
{
  DEBUGWHERE();
  start_timer(0);
  catch_timer(0);
  portalPerfRequestProxy->swallowlll(vl1, vl2, vl3);
  catch_timer(19);
}

void call_swallowllll(void)
{
  DEBUGWHERE();
  start_timer(0);
  catch_timer(0);
  portalPerfRequestProxy->swallowllll(vl1, vl2, vl3, vl4);
  catch_timer(19);
}

void call_swallowd(void)
{
  DEBUGWHERE();
  start_timer(0);
  catch_timer(0);
  portalPerfRequestProxy->swallowd(vd1);
  catch_timer(19);
}

void call_swallowdd(void)
{
  DEBUGWHERE();
  start_timer(0);
  catch_timer(0);
  portalPerfRequestProxy->swallowdd(vd1, vd2);
  catch_timer(19);
}

void call_swallowddd(void)
{
  DEBUGWHERE();
  start_timer(0);
  catch_timer(0);
  portalPerfRequestProxy->swallowddd(vd1, vd2, vd3);
  catch_timer(19);
}

void call_swallowdddd(void)
{
  DEBUGWHERE();
  start_timer(0);
  catch_timer(0);
  portalPerfRequestProxy->swallowdddd(vd1, vd2, vd3, vd4);
  catch_timer(19);
}

void dotestout(const char *testname, void (*testfn)(void))
{
  uint64_t elapsed;
  init_timer();
  start_timer(1);
  for (int i = 0; i < LOOP_COUNT; i++) {
    testfn();
  }
  elapsed = lap_timer(1);
  printf("test %s: elapsed %g average %g\n", testname, (double) elapsed, (double) elapsed/ (double) LOOP_COUNT);
  print_timer(LOOP_COUNT);
}

void dotestin(const char *testname, int which)
{
  uint64_t elapsed;
  heard_count = 0;
  printf("starting test %s, which %d\n", testname, which);
  init_timer();
  start_timer(1);
  start_timer(0);
  catch_timer(0);
  portalPerfRequestProxy->startspit(which, LOOP_COUNT);
  catch_timer(19);
  wait_for(LOOP_COUNT);
  catch_timer(21);
  elapsed = lap_timer(1);
  printf("test %s: heard %d elapsed %g average %g\n", testname, heard_count, (double) elapsed, (double) elapsed/ (double) LOOP_COUNT);
  print_timer(1);
}

int main(int argc, const char **argv)
{
    PortalPerfIndication *portalPerfIndication = new PortalPerfIndication(IfcNames_PortalPerfIndication);

    portalPerfRequestProxy = new PortalPerfRequestProxy(IfcNames_PortalPerfRequest);

    portalExec_init();

    printf("Timer tests\n");
    init_timer();
    for (int i = 0; i < 1000; i++) {
      start_timer(0);
      catch_timer(1);
      catch_timer(2);
      catch_timer(3);
      catch_timer(4);
      catch_timer(5);
      catch_timer(6);
      catch_timer(7);
      catch_timer(8);
    }
    printf("Each line 1-8 is one more call to catch_timer()\n");
    print_timer(1000);

    vl1 = 0xfeed000000000011;
    vl2 = 0xface000000000012;
    vl3 = 0xdead000000000013;
    vl4 = 0xbeef000000000014;
    vd1 = 0xfeed0000000000000021LL;
    vd2 = 0xface0000000000000022LL;
    vd3 = 0xdead0000000000000023LL;
    vd4 = 0xbeef0000000000000024LL;

    dotestout("swallow", call_swallow);
    dotestout("swallowl", call_swallowl);
    dotestout("swallowll", call_swallowll);
    dotestout("swallowlll", call_swallowlll);
    dotestout("swallowllll", call_swallowllll);
    dotestout("swallowd", call_swallowd);
    dotestout("swallowdd", call_swallowdd);
    dotestout("swallowddd", call_swallowddd);
    dotestout("swallowdddd", call_swallowdddd);
    dotestin("spitl", 1);
    dotestin("spit", 0);
    dotestin("spitll", 2);
    dotestin("spitlll", 3);
    dotestin("spitllll", 4);
    dotestin("spitd", 5);
    dotestin("spitdd", 6);
    dotestin("spitddd", 7);
    dotestin("spitdddd", 8);

    portalExec_end();
    return 0;
}
