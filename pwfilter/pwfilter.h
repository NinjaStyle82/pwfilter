// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the PWFILTER_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// PWFILTER_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef PWFILTER_EXPORTS
#define PWFILTER_API extern "C" __declspec(dllexport)
#else
#define PWFILTER_API extern "C" __declspec(dllexport)
#endif
// This class is exported from the dll
//class PWFILTER_API Cpwfilter {
//public:
//	Cpwfilter(void);
	// TODO: add your methods here.
//};

//extern PWFILTER_API int npwfilter;

//PWFILTER_API int fnpwfilter(void);