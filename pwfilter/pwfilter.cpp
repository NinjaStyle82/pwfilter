// pwfilter.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "pwfilter.h"

using namespace std;

VOID outFile(string Str)
{
	using namespace std;
	ofstream myfile("pwfilter.txt",ios::app);
	if (myfile.is_open())
	{
		myfile << Str+"\n";
		myfile.close();
	}
}

PWFILTER_API BOOLEAN __stdcall InitializeChangeNotify(VOID)
{
	outFile("Entered InitializeChangeNotify");
	return TRUE;
}

PWFILTER_API NTSTATUS __stdcall PasswordChangeNotify(
	PUNICODE_STRING UserName,
	ULONG RelativeId,
	PUNICODE_STRING NewPassword
)
{
	outFile("Entered PasswordChangeNotify");
	return S_OK;
}

bool computeHash(const string &unhashed, string &hashed)
{
	bool success = false;

	EVP_MD_CTX* context = EVP_MD_CTX_create();

	if (context != NULL)
	{
		if (EVP_DigestInit_ex(context, EVP_sha1(), NULL))
		{
			if (EVP_DigestUpdate(context, unhashed.c_str(), unhashed.length()))
			{
				unsigned char hash[EVP_MAX_MD_SIZE];
				unsigned int lengthOfHash = 0;

				if (EVP_DigestFinal_ex(context, hash, &lengthOfHash))
				{
					stringstream ss;
					for (unsigned int i = 0; i < lengthOfHash; i++)
					{
						ss << hex << setw(2) << setfill('0') << (int)hash[i];
					}
					hashed = ss.str();
					success = true;
				}
			}
		}

		EVP_MD_CTX_destroy(context);
	}
	return success;
}
 string makeShaHash(string sPassword)
{
	outFile("Entered makeShaHash");

	string hash;

	bool returnValue = computeHash(sPassword, hash);
	if (returnValue)
	{
		outFile(hash);
		transform(hash.begin(), hash.end(), hash.begin(), ::toupper);
		return hash;
	}
	else
	{
		return "";
	}

}
struct MemoryStruct {
	char* memory;
	size_t size;
};

static size_t
WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct* mem = (struct MemoryStruct*)userp;

	char* ptr = (char*)realloc(mem->memory, mem->size + realsize + 1);
	if (ptr == NULL) {
		/* out of memory! */
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}
BOOLEAN checkHibp(PUNICODE_STRING Password)
{

	PWSTR pwbuffer = Password->Buffer;
	wstring wPassword(pwbuffer);
	using convert_type = codecvt_utf8<wchar_t>;
	wstring_convert<convert_type, wchar_t> converter;
	string sPassword = converter.to_bytes(wPassword);
	outFile(sPassword);
	string sha1Hash = makeShaHash(sPassword);

	string ppUrl = "https://api.pwnedpasswords.com/range/"+sha1Hash.substr(0, 5);
	CURL* curl;
	CURLcode res;

	struct MemoryStruct chunk;

	chunk.memory = (char*)malloc(1);  /* will be grown as needed by the realloc above */
	chunk.size = 0;    /* no data at this point */
	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, ppUrl.c_str());
		/* example.com is redirected, so we tell libcurl to follow redirection */
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		/* send all data to this function  */
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		/* we pass our 'chunk' struct to the callback function */
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
		/* some servers don't like requests that are made without a user-agent
		   field, so we provide one */
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);
		/* Check for errors */
		if (res != CURLE_OK)
		{
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		}else {
			/*
			 * Now, our chunk.memory points to a memory block that is chunk.size
			 * bytes big and contains the remote file.
			 *
			 * Do something nice with it!
			 */

			printf("%lu bytes retrieved\n", (unsigned long)chunk.size);
		}
		size_t hashmatch(0);
		if (chunk.size > 0) {
			string hashlist = (string)chunk.memory;
			//match the hash suffix from the returned data
			hashmatch = hashlist.find(sha1Hash.substr(5,string::npos));
		}
		/* cleanup curl stuff */
		curl_easy_cleanup(curl);
		free(chunk.memory);
		/* we're done with libcurl, so clean it up */
		curl_global_cleanup();
		// return true if no match was found, else return false
		if (hashmatch == string::npos)
			return TRUE;
		else
			return FALSE;
	}

}
PWFILTER_API VOID __stdcall test()
{
	UNICODE_STRING punipw{};
	RtlInitUnicodeString(&punipw, L"tesdlvsdvlslvsldvsldvsdlst");

	checkHibp(&punipw);
}

PWFILTER_API BOOLEAN __stdcall PasswordFilter(
	PUNICODE_STRING AccountName,
	PUNICODE_STRING FullName,
	PUNICODE_STRING Password,
	BOOLEAN SetOperation
)
{
	outFile("Entered PasswordFilter");
	return checkHibp(Password);
}