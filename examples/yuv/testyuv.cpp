
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
#include <assert.h>

#include "YuvIndicationWrapper.h"
#include "YuvRequestProxy.h"
#include "GeneratedTypes.h"

struct rgb {
  unsigned char r;
  unsigned char g;
  unsigned char b;
  int operator==(const struct rgb &o) { return r == o.r && g == o.g && b == o.b; }
};
struct yuv {
  unsigned char y;
  unsigned char u;
  unsigned char v;
  int operator==(const struct yuv &o) { return y == o.y && u == o.u && v == o.v; }
};

struct rgb expected_rgb;
struct yuv expected_yuv;

static int numTests = 0;
class YuvIndication : public YuvIndicationWrapper
{  
public:
  uint32_t cnt;
  void incr_cnt(){
    if (++cnt >= numTests)
      exit(0);
  }
  virtual void rgb(uint32_t r, uint32_t g, uint32_t b) {
    fprintf(stderr, "rgb(%d,%d,%d)\n", r, g, b);
    struct rgb answer = {r, g, b};
    assert(expected_rgb == answer);
    incr_cnt();
  }
  virtual void yuv(uint32_t y, uint32_t u, uint32_t v) {
    fprintf(stderr, "yuv(%d,%d,%d)\n", y, u, v);
    struct yuv answer = {y,u,v};
    assert(expected_yuv == answer);
    incr_cnt();
  }
  virtual void yyuv(uint32_t yy, uint32_t uv) {
    fprintf(stderr, "yyuv(%d,%d)\n", yy, uv);
    //    assert(a == v1a);
    incr_cnt();
  }

  YuvIndication(unsigned int id) : YuvIndicationWrapper(id), cnt(0){}
};

struct yuv rgbtoyuv(unsigned short r, unsigned short g, unsigned short b)
{
  unsigned char y = ( 77*r + 150*g +  29*b + 0) >> 8;
  unsigned char u = (-43*r -  85*g + 128*b + 128) >> 8;
  unsigned char v = (128*r - 107*g -  21*b + 128) >> 8;
  fprintf(stderr, "rgb %d,%d,%d -> yuv %d,%d,%d\n", r, g, b, y, u, v);
  return { y, u, v };
}

int main(int argc, const char **argv)
{
  YuvIndication *indication = new YuvIndication(IfcNames_YuvIndicationPortal);
  YuvRequestProxy *device = new YuvRequestProxy(IfcNames_YuvRequestPortal);

  pthread_t tid;
  fprintf(stderr, "Main::creating exec thread\n");
  if(pthread_create(&tid, NULL,  portalExec, NULL)){
    fprintf(stderr, "Main::error creating exec thread\n");
    exit(1);
  }

  struct rgb tests[] = {
    { 0, 0, 0 },
    { 1, 2, 3 },
    { 128, 0, 0 },
    { 0, 128, 0 },
    { 0, 0, 128 },
    { 255, 0, 0 },
    { 0, 255, 0 },
    { 0, 0, 255 },
    { 255, 255, 255 },
  };

  numTests++;

  for (int i = 0; i < sizeof(tests)/sizeof(struct rgb); i++) {
    expected_rgb = tests[i];
    expected_yuv = rgbtoyuv(tests[i].r, tests[i].g, tests[i].b);
    numTests++; device->toRgb(tests[i].r, tests[i].g, tests[i].b);
    numTests++; device->toYuv(tests[i].r, tests[i].g, tests[i].b);
    numTests++; device->toYyuv(tests[i].r, tests[i].g, tests[i].b);
    sleep(1);
  }

  expected_rgb = tests[0];
  device->toRgb(tests[0].r, tests[0].g, tests[0].b); // now we're done

  fprintf(stderr, "Main::about to go to sleep\n");
  while(true){sleep(2);}
}
