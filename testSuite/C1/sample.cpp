// 456.hmmer spec benchmark LC case

#include <iostream>
#include <cstdlib>

using namespace std;

typedef void (*fnptr)();

void CallA() { cout << "Target A" << endl; }

void CallB() { cout << "Target B" << endl; }

void CallC() { cout << "Target C" << endl; }

typedef struct hmStruct {
  char s[5];
  fnptr fp;
} hmmer;

hmmer *SampleOpen(int a) {
  hmmer *hm;
  hm = (hmmer *)malloc(sizeof(hmmer));
  hm->fp = NULL;

  if (a > 20) {
    hm->fp = &CallA;
  }
  if (a > 10) {
    hm->fp = &CallA;
  } else {
    hm->fp = &CallB;
  }
  cin >> (hm->s);
  return hm;
}

void SampleRead(hmmer *hm) {
  hm->fp();
  return;
}

void ctx() {
  int a;
  cin >> a;
  hmmer *mhm = SampleOpen(a);
  SampleRead(mhm);
}

int main() {
  ctx();
  return 0;
}