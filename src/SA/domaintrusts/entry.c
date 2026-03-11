#include <windows.h>
#include "bofdefs.h"
#include "base.c"

#ifndef TRUST_TYPE_DCE
#define TRUST_TYPE_DCE 4
#endif

#ifndef TRUST_ATTRIBUTE_FILTER_SIDS
#define TRUST_ATTRIBUTE_FILTER_SIDS         0x00000004
#endif
#ifndef TRUST_ATTRIBUTE_CROSS_ORGANIZATION
#define TRUST_ATTRIBUTE_CROSS_ORGANIZATION  0x00000010
#endif
#ifndef TRUST_ATTRIBUTE_WITHIN_FOREST
#define TRUST_ATTRIBUTE_WITHIN_FOREST       0x00000020
#endif
#ifndef TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL
#define TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL   0x00000040
#endif

void enumDomainTrusts(wchar_t *serverName)
{
    PDS_DOMAIN_TRUSTSW pDomains = NULL;
    ULONG domainCount = 0;
    DWORD status;

    status = NETAPI32$DsEnumerateDomainTrustsW(serverName, DS_DOMAIN_VALID_FLAGS, (PVOID *)&pDomains, &domainCount);
    if (status != ERROR_SUCCESS)
    {
        internal_printf("DsEnumerateDomainTrustsW failed: %lu\n", status);
        return;
    }

    if (pDomains == NULL || domainCount == 0)
    {
        internal_printf("No domain trusts found.\n");
        if (pDomains) NETAPI32$NetApiBufferFree(pDomains);
        return;
    }

    internal_printf("Domain trusts (%lu found):\n", domainCount);
    internal_printf("==================================================\n");

    for (ULONG i = 0; i < domainCount; i++)
    {
        PDS_DOMAIN_TRUSTSW t = &pDomains[i];

        internal_printf("\n[%lu] NetBIOS: %S\n", i, t->NetbiosDomainName ? t->NetbiosDomainName : L"(null)");
        internal_printf("     DNS:     %S\n", t->DnsDomainName ? t->DnsDomainName : L"(null)");

        /* Flags */
        internal_printf("     Flags:   0x%04lx (", t->Flags);
        int first = 1;
        if (t->Flags & DS_DOMAIN_IN_FOREST)       { internal_printf("%sIN_FOREST", first ? "" : "|"); first = 0; }
        if (t->Flags & DS_DOMAIN_DIRECT_OUTBOUND)  { internal_printf("%sDIRECT_OUTBOUND", first ? "" : "|"); first = 0; }
        if (t->Flags & DS_DOMAIN_TREE_ROOT)        { internal_printf("%sTREE_ROOT", first ? "" : "|"); first = 0; }
        if (t->Flags & DS_DOMAIN_PRIMARY)          { internal_printf("%sPRIMARY", first ? "" : "|"); first = 0; }
        if (t->Flags & DS_DOMAIN_NATIVE_MODE)      { internal_printf("%sNATIVE_MODE", first ? "" : "|"); first = 0; }
        if (t->Flags & DS_DOMAIN_DIRECT_INBOUND)   { internal_printf("%sDIRECT_INBOUND", first ? "" : "|"); first = 0; }
        if (first) internal_printf("NONE");
        internal_printf(")\n");

        /* Parent index */
        internal_printf("     Parent:  %lu\n", t->ParentIndex);

        /* Trust type */
        const char *typeStr;
        switch (t->TrustType)
        {
            case TRUST_TYPE_DOWNLEVEL: typeStr = "Downlevel"; break;
            case TRUST_TYPE_UPLEVEL:   typeStr = "Uplevel"; break;
            case TRUST_TYPE_MIT:       typeStr = "MIT"; break;
            case TRUST_TYPE_DCE:       typeStr = "DCE"; break;
            default:                   typeStr = "Unknown"; break;
        }
        internal_printf("     Type:    %lu (%s)\n", t->TrustType, typeStr);

        /* Trust attributes */
        internal_printf("     Attrib:  0x%08lx (", t->TrustAttributes);
        first = 1;
        if (t->TrustAttributes & TRUST_ATTRIBUTE_NON_TRANSITIVE)     { internal_printf("%sNON_TRANSITIVE", first ? "" : "|"); first = 0; }
        if (t->TrustAttributes & TRUST_ATTRIBUTE_UPLEVEL_ONLY)       { internal_printf("%sUPLEVEL_ONLY", first ? "" : "|"); first = 0; }
        if (t->TrustAttributes & TRUST_ATTRIBUTE_FILTER_SIDS)        { internal_printf("%sFILTER_SIDS", first ? "" : "|"); first = 0; }
        if (t->TrustAttributes & TRUST_ATTRIBUTE_FOREST_TRANSITIVE)  { internal_printf("%sFOREST_TRANSITIVE", first ? "" : "|"); first = 0; }
        if (t->TrustAttributes & TRUST_ATTRIBUTE_CROSS_ORGANIZATION) { internal_printf("%sCROSS_ORGANIZATION", first ? "" : "|"); first = 0; }
        if (t->TrustAttributes & TRUST_ATTRIBUTE_WITHIN_FOREST)      { internal_printf("%sWITHIN_FOREST", first ? "" : "|"); first = 0; }
        if (t->TrustAttributes & TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL)  { internal_printf("%sTREAT_AS_EXTERNAL", first ? "" : "|"); first = 0; }
        if (first) internal_printf("NONE");
        internal_printf(")\n");

        /* SID */
        if (t->DomainSid)
        {
            LPSTR sidStr = NULL;
            if (ADVAPI32$ConvertSidToStringSidA(t->DomainSid, &sidStr))
            {
                internal_printf("     SID:     %s\n", sidStr);
                KERNEL32$LocalFree(sidStr);
            }
            else
            {
                internal_printf("     SID:     (conversion failed)\n");
            }
        }
        else
        {
            internal_printf("     SID:     (null)\n");
        }

        /* GUID */
        RPC_CSTR guidStr = NULL;
        if (RPCRT4$UuidToStringA(&t->DomainGuid, &guidStr) == RPC_S_OK)
        {
            internal_printf("     GUID:    %s\n", guidStr);
            RPCRT4$RpcStringFreeA(&guidStr);
        }
        else
        {
            internal_printf("     GUID:    (conversion failed)\n");
        }
    }

    NETAPI32$NetApiBufferFree(pDomains);
}

#ifdef BOF

VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    datap parser = {0};
    BeaconDataParse(&parser, Buffer, Length);

    wchar_t *serverName = (wchar_t *)BeaconDataExtract(&parser, NULL);
    if (*serverName == 0)
    {
        serverName = NULL;
    }

    if (!bofstart())
    {
        return;
    }

    enumDomainTrusts(serverName);

    printoutput(TRUE);
}

#else

int main()
{
    enumDomainTrusts(NULL);
    return 0;
}

#endif
