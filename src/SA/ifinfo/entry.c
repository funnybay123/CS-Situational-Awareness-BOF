#include <windows.h>
#include <iphlpapi.h>
#include "bofdefs.h"
#include "base.c"

/*
 * MIB_IF_ROW2 / MIB_IF_TABLE2 structures and related constants.
 * MinGW cross-compilation headers may not provide these (requires Vista+).
 * We define them here to ensure portability.
 */

#ifndef IF_MAX_STRING_SIZE
#define IF_MAX_STRING_SIZE 256
#endif

#ifndef IF_MAX_PHYS_ADDRESS_LENGTH
#define IF_MAX_PHYS_ADDRESS_LENGTH 32
#endif

#ifndef IF_TYPE_SOFTWARE_LOOPBACK
#define IF_TYPE_SOFTWARE_LOOPBACK 24
#endif

#ifndef IF_TYPE_ETHERNET_CSMACD
#define IF_TYPE_ETHERNET_CSMACD 6
#endif

#ifndef IF_TYPE_IEEE80211
#define IF_TYPE_IEEE80211 71
#endif

#ifndef IF_TYPE_TUNNEL
#define IF_TYPE_TUNNEL 131
#endif

#ifndef IF_TYPE_PPP
#define IF_TYPE_PPP 23
#endif

/* OperStatus values */
#define MY_IfOperStatusUp             1
#define MY_IfOperStatusDown           2
#define MY_IfOperStatusTesting        3
#define MY_IfOperStatusUnknown        4
#define MY_IfOperStatusDormant        5
#define MY_IfOperStatusNotPresent     6
#define MY_IfOperStatusLowerLayerDown 7

/* AdminStatus values */
#define MY_NET_IF_ADMIN_STATUS_UP      1
#define MY_NET_IF_ADMIN_STATUS_DOWN    2
#define MY_NET_IF_ADMIN_STATUS_TESTING 3

/* ConnectionType values */
#define MY_NET_IF_CONNECTION_DEDICATED 1
#define MY_NET_IF_CONNECTION_PASSIVE   2
#define MY_NET_IF_CONNECTION_DEMAND    3

/* MediaConnectState */
#define MY_MediaConnectStateUnknown      0
#define MY_MediaConnectStateConnected    1
#define MY_MediaConnectStateDisconnected 2

typedef struct _MY_MIB_IF_ROW2 {
    NET_LUID InterfaceLuid;
    NET_IFINDEX InterfaceIndex;
    GUID InterfaceGuid;
    WCHAR Alias[IF_MAX_STRING_SIZE + 1];
    WCHAR Description[IF_MAX_STRING_SIZE + 1];
    ULONG PhysicalAddressLength;
    UCHAR PhysicalAddress[IF_MAX_PHYS_ADDRESS_LENGTH];
    UCHAR PermanentPhysicalAddress[IF_MAX_PHYS_ADDRESS_LENGTH];
    ULONG Mtu;
    IFTYPE Type;
    TUNNEL_TYPE TunnelType;
    DWORD MediaType;            /* NDIS_MEDIUM */
    DWORD PhysicalMediumType;   /* NDIS_PHYSICAL_MEDIUM */
    DWORD AccessType;           /* NET_IF_ACCESS_TYPE */
    DWORD DirectionType;        /* NET_IF_DIRECTION_TYPE */
    struct {
        BOOLEAN HardwareInterface : 1;
        BOOLEAN FilterInterface : 1;
        BOOLEAN ConnectorPresent : 1;
        BOOLEAN NotAuthenticated : 1;
        BOOLEAN NotMediaConnected : 1;
        BOOLEAN Paused : 1;
        BOOLEAN LowPower : 1;
        BOOLEAN EndPointInterface : 1;
    } InterfaceAndOperStatusFlags;
    DWORD OperStatus;           /* IF_OPER_STATUS */
    DWORD AdminStatus;          /* NET_IF_ADMIN_STATUS */
    DWORD MediaConnectState;    /* NET_IF_MEDIA_CONNECT_STATE */
    NET_IF_NETWORK_GUID NetworkGuid;
    DWORD ConnectionType;       /* NET_IF_CONNECTION_TYPE */
    ULONG64 TransmitLinkSpeed;
    ULONG64 ReceiveLinkSpeed;
    ULONG64 InOctets;
    ULONG64 InUcastPkts;
    ULONG64 InNUcastPkts;
    ULONG64 InDiscards;
    ULONG64 InErrors;
    ULONG64 InUnknownProtos;
    ULONG64 InUcastOctets;
    ULONG64 InMulticastOctets;
    ULONG64 InBroadcastOctets;
    ULONG64 OutOctets;
    ULONG64 OutUcastPkts;
    ULONG64 OutNUcastPkts;
    ULONG64 OutDiscards;
    ULONG64 OutErrors;
    ULONG64 OutUcastOctets;
    ULONG64 OutMulticastOctets;
    ULONG64 OutBroadcastOctets;
    ULONG64 OutQLen;
} MY_MIB_IF_ROW2;

typedef struct _MY_MIB_IF_TABLE2 {
    ULONG NumEntries;
    MY_MIB_IF_ROW2 Table[1];
} MY_MIB_IF_TABLE2;


static const char* iftype_to_str(IFTYPE type)
{
    switch(type) {
        case 1:                         return "Other";
        case IF_TYPE_ETHERNET_CSMACD:   return "Ethernet";
        case IF_TYPE_PPP:               return "PPP";
        case IF_TYPE_SOFTWARE_LOOPBACK: return "Loopback";
        case IF_TYPE_TUNNEL:            return "Tunnel";
        case IF_TYPE_IEEE80211:         return "Wi-Fi";
        case 53:                        return "Virtual/Proprietary";
        default:                        return "Other";
    }
}

static const char* operstatus_to_str(DWORD status)
{
    switch(status) {
        case MY_IfOperStatusUp:             return "Up";
        case MY_IfOperStatusDown:           return "Down";
        case MY_IfOperStatusTesting:        return "Testing";
        case MY_IfOperStatusUnknown:        return "Unknown";
        case MY_IfOperStatusDormant:        return "Dormant";
        case MY_IfOperStatusNotPresent:     return "Not Present";
        case MY_IfOperStatusLowerLayerDown: return "Lower Layer Down";
        default:                            return "Unknown";
    }
}

static const char* adminstatus_to_str(DWORD status)
{
    switch(status) {
        case MY_NET_IF_ADMIN_STATUS_UP:      return "Up";
        case MY_NET_IF_ADMIN_STATUS_DOWN:    return "Down";
        case MY_NET_IF_ADMIN_STATUS_TESTING: return "Testing";
        default:                             return "Unknown";
    }
}

static const char* conntype_to_str(DWORD type)
{
    switch(type) {
        case MY_NET_IF_CONNECTION_DEDICATED: return "Dedicated";
        case MY_NET_IF_CONNECTION_PASSIVE:   return "Passive";
        case MY_NET_IF_CONNECTION_DEMAND:    return "Demand";
        default:                             return "Unknown";
    }
}

static const char* mediaconnect_to_str(DWORD state)
{
    switch(state) {
        case MY_MediaConnectStateConnected:    return "Connected";
        case MY_MediaConnectStateDisconnected: return "Disconnected";
        default:                               return "Unknown";
    }
}

static void format_speed(ULONG64 bps, char* buf, int buflen)
{
    if (bps >= 1000000000ULL)
        MSVCRT$sprintf(buf, "%llu.%llu Gbps", (unsigned long long)(bps / 1000000000ULL), (unsigned long long)((bps % 1000000000ULL) / 100000000ULL));
    else if (bps >= 1000000ULL)
        MSVCRT$sprintf(buf, "%llu Mbps", (unsigned long long)(bps / 1000000ULL));
    else if (bps >= 1000ULL)
        MSVCRT$sprintf(buf, "%llu Kbps", (unsigned long long)(bps / 1000ULL));
    else
        MSVCRT$sprintf(buf, "%llu bps", (unsigned long long)bps);
}

static void format_bytes(ULONG64 bytes, char* buf, int buflen)
{
    if (bytes >= (1024ULL * 1024 * 1024))
        MSVCRT$sprintf(buf, "%llu.%llu GB", (unsigned long long)(bytes / (1024ULL * 1024 * 1024)), (unsigned long long)((bytes % (1024ULL * 1024 * 1024)) / (1024ULL * 1024 * 100)));
    else if (bytes >= (1024ULL * 1024))
        MSVCRT$sprintf(buf, "%llu.%llu MB", (unsigned long long)(bytes / (1024ULL * 1024)), (unsigned long long)((bytes % (1024ULL * 1024)) / (1024ULL * 100)));
    else if (bytes >= 1024ULL)
        MSVCRT$sprintf(buf, "%llu KB", (unsigned long long)(bytes / 1024ULL));
    else
        MSVCRT$sprintf(buf, "%llu B", (unsigned long long)bytes);
}

void ifinfo()
{
    DWORD ret;
    MY_MIB_IF_TABLE2 *pTable = NULL;
    ULONG i;

    ret = IPHLPAPI$GetIfTable2((PVOID*)&pTable);
    if (ret != NO_ERROR)
    {
        BeaconPrintf(CALLBACK_ERROR, "GetIfTable2 failed with error: %d", ret);
        return;
    }

    internal_printf("\n===== Network Interface Information =====\n");
    internal_printf("Total interfaces: %lu\n\n", pTable->NumEntries);

    for (i = 0; i < pTable->NumEntries; i++)
    {
        MY_MIB_IF_ROW2 *row = &pTable->Table[i];
        char *alias = NULL;
        char *desc = NULL;
        char macStr[64] = {0};
        char txSpeed[64] = {0};
        char rxSpeed[64] = {0};
        char inBytes[64] = {0};
        char outBytes[64] = {0};
        ULONG j;

        /* Skip loopback interfaces */
        if (row->Type == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        alias = Utf16ToUtf8(row->Alias);
        desc  = Utf16ToUtf8(row->Description);

        internal_printf("--- Interface #%lu (Index: %lu) ---\n", i, row->InterfaceIndex);
        internal_printf("  Alias:            %s\n", alias ? alias : "(null)");
        internal_printf("  Description:      %s\n", desc ? desc : "(null)");
        internal_printf("  Type:             %s (%lu)\n", iftype_to_str(row->Type), (unsigned long)row->Type);
        internal_printf("  MTU:              %lu\n", (unsigned long)row->Mtu);

        /* MAC address */
        if (row->PhysicalAddressLength > 0 && row->PhysicalAddressLength <= IF_MAX_PHYS_ADDRESS_LENGTH)
        {
            macStr[0] = '\0';
            for (j = 0; j < row->PhysicalAddressLength; j++)
            {
                char tmp[4];
                if (j > 0)
                    MSVCRT$sprintf(tmp, "-%02X", row->PhysicalAddress[j]);
                else
                    MSVCRT$sprintf(tmp, "%02X", row->PhysicalAddress[j]);
                MSVCRT$strcat(macStr, tmp);
            }
            internal_printf("  Physical Address: %s\n", macStr);
        }

        internal_printf("  Admin Status:     %s\n", adminstatus_to_str(row->AdminStatus));
        internal_printf("  Oper Status:      %s\n", operstatus_to_str(row->OperStatus));
        internal_printf("  Media State:      %s\n", mediaconnect_to_str(row->MediaConnectState));
        internal_printf("  Connection Type:  %s\n", conntype_to_str(row->ConnectionType));

        format_speed(row->TransmitLinkSpeed, txSpeed, sizeof(txSpeed));
        format_speed(row->ReceiveLinkSpeed, rxSpeed, sizeof(rxSpeed));
        internal_printf("  Transmit Speed:   %s\n", txSpeed);
        internal_printf("  Receive Speed:    %s\n", rxSpeed);

        /* Traffic statistics */
        format_bytes(row->InOctets, inBytes, sizeof(inBytes));
        format_bytes(row->OutOctets, outBytes, sizeof(outBytes));
        internal_printf("  --- Traffic Statistics ---\n");
        internal_printf("  Bytes In:         %s (%llu)\n", inBytes, (unsigned long long)row->InOctets);
        internal_printf("  Bytes Out:        %s (%llu)\n", outBytes, (unsigned long long)row->OutOctets);
        internal_printf("  Packets In:       %llu (unicast)\n", (unsigned long long)row->InUcastPkts);
        internal_printf("  Packets Out:      %llu (unicast)\n", (unsigned long long)row->OutUcastPkts);
        internal_printf("  Errors In:        %llu\n", (unsigned long long)row->InErrors);
        internal_printf("  Errors Out:       %llu\n", (unsigned long long)row->OutErrors);
        internal_printf("  Discards In:      %llu\n", (unsigned long long)row->InDiscards);
        internal_printf("  Discards Out:     %llu\n", (unsigned long long)row->OutDiscards);
        internal_printf("\n");

        if (alias) intFree(alias);
        if (desc)  intFree(desc);
    }

    IPHLPAPI$FreeMibTable(pTable);
}


#ifdef BOF

VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    if(!bofstart())
    {
        return;
    }
    ifinfo();
    printoutput(TRUE);
};

#else

int main()
{
    ifinfo();
    return 0;
}

#endif
