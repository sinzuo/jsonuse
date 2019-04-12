/*
 *  * 主函数
 *   */


#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include <sys/wait.h>

#include <sys/msg.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <pthread.h>
#include "json.h"

#define	__WEXITSTATUS(status)	(((status) & 0xff00) >> 8)
#define WEXITSTATUS(status)	__WEXITSTATUS (status)

#define	__WTERMSIG(status)	((status) & 0x7f)
#define	__WIFEXITED(status)	(__WTERMSIG(status) == 0)
#define WIFEXITED(status)	__WIFEXITED (status)

#define MIN_FIELD_LEN 20
#define NORMAL_FIELD_LEN 256
#define URL_ENCODING_FIELD_LEN 100 * 3
#define MAX_FIELD_LEN 256
#define BIG_MAX_FIELD_LEN 1024

#define NORMAL_ARRAY_SIZE 100
#define MINI_ARRAY_SIZE 50

#define NORMAL_USER "a6083050"
#define ADMIN_USER "b8faec00"
#define SUPER_ADMIN_USER "dfa39cda"
#define NORMAL_USER_LOGIN_FLAG_FILE "/tmp/.normal_user_login_flag"
#define ADMIN_USER_LOGIN_FLAG_FILE "/tmp/.admin_user_login_flag"
#define TEST_USER_LOGIN_FLAG_FILE "/tmp/.test_user_login_flag"

#define LAN_INFO "/proc/phys26/link"
#define WAN_INFO "/proc/wan_is_using"

#define CONFIG_FILE_NAME "cat /tmp/rc.system.conf"
#define CONFIG_COMMIT "cfg -c > /tmp/cfg 2>&1"

#define UPTIME_FILE_NAME "uptime"
#define CONFIG_TMP_FILE_NAME "/tmp/rc.system.conf"
#define SESSION_FILE_NAME "/tmp/.sessionId"
#define PROC_TOZED_IND "/proc/tozed/ind"
#define PROC_TOZED_SMSIND "/proc/tozed/smsind"
#define PROC_TOZED_SMSREADY "/proc/tozed/smsready"
#define PROC_TOZED_USB "/proc/tozed/usbserialind"
#define PROC_TOZED_WATCHDOG "/proc/tozed/watchdog"
#define PROC_NET_DEV "/proc/net/dev"
#define RC_SYSTEM_CONF "/etc/rc.d/rc.system.conf"

#define TMP_FAIL_LOGIN_TIMES_FILE		"/tmp/.login_fail_times"
#define TEMP_DIALTOOL_INDICATOR		"/tmp/.dialtool_indicator"
#define TEMP_LOG_FILE "/tmp/temp.log"

#define LAN_INTERFACES_INFO "eth1"
#define WAN_INTERFACES_INFO "ifconfig usb0"

#define READ_DNS "cat /etc/resolv.conf | grep -v \'#\' | grep \'nameserver\'"
#define DNS_FILE_NAME "/etc/resolv.conf"
#define ROUTE_FILE_NAME "/proc/net/route"
#define IPV6_ROUTE_FILE_NAME "/proc/net/ipv6_route"
#define IPV6_IF_FILE_NAME "/proc/net/if_inet6"
#define READ_GATEWAY "route -n | grep \'^0.0.0.0\'"  

#define VERSION_FILE_NAME "/version"
#define SYSTEM_INFO_STATIC "/tmp/.system_info_static"
#define SYSTEM_INFO_DYNAMIC "/tmp/.system_info_dynamic"
#define LTE_VERSION_FILE_NAME "/tmp/.moduleinfo"
#define SCANLAST_FILE_NAME "/tmp/scanlast"
#define SPEED_MODE_FILE_NAME "/tmp/cpe_speed_mode"
#define TMP_SIM_LOCKING_FILE_NAME "/tmp/.tmp_sim_locking"
#define TMP_SIM_IS_LOCKED_FILE_NAME "/tmp/.tmp_sim_is_locked"
#define STATIC_LEASE_FILE_NAME "/etc/rc.d/rc.dhcp.static"

#define DEFAULT_USER_NAME "admin"
#define DEFAULT_PASSWD "21232f297a57a5a743894a0e4a801fc3"

#define DEFAULT_TEST_USER_NAME "sztozedtest"
#define DEFAULT_TEST_PASSWD "c4e55e95790664da8dde67a97740c0a5"

#define CALCULATE_START_YEAR 2012
#define VERSION_UPDATE_FILE_NAME "/tmp/.update.version"

#define FLOW_STATISTICS_FILE_NAME "/tmp/usb0statistics"
#define SYS_LOG_FILE_NAME "/mnt/usr/websys.log"

#define SMS_RECEIVE_DIR SMS_CONTENT_FOLDER
#define SMS_SEND_DIR "/mnt/usr/sms_send"
#define SMS_COUNT_FILE_NAME "/tmp/.sms_count_info"

// 关闭管理功能和上网功能标识
#define CLOSE_LOCAL_MANAGE "/tmp/.close_local_manage"

#define TR069_INFORM_FLAG_FILE "/tmp/.tr069_inform_flag"

#define INT_SIZE 12
#define MAX_SMS_SIZE 100
#define SMS_CONTENT_SIZE 1801
#define SMS_COMMON_SIZE 24

#define IPV4 "iptables "
#define IPV6 "ip6tables "

// 短消息存储格式
#define SMS_DIR_FIELDS_SIZE 11
#define SMS_FILE_FIELDS_SIZE 6

#define SAVE_NO_SEND_SMS "2"
#define SAVE_SENDED_SMS "3"

#define SEND_SMS "1"

#define DEBUG 0

#define MF210_IS_USED "/tmp/.module_mf210_is_used"
#define SIM5360_IS_USED "/tmp/.module_sim5360_is_used"
#define MC2716_IS_USED "/tmp/.module_mc2716_is_used"
#define C5300V_IS_USED "/tmp/.module_c5300v_is_used"


#define ARRAY_LENGTH(ARRAY_NAME) ( sizeof( ARRAY_NAME )/sizeof( ARRAY_NAME[0] ) )


enum RETURN_CODE {
	SUCCESS = 0,
	FAIL = 1,
	ERROR = 2
};

enum REQUEST_COMMAND {
	SYS_INFO = 0,
	WIRELESS_INFO = 1,
	WIRELESS_CONFIG = 2,
	NETWORK_CONFIG = 3,
	USER_INFO = 4,
	SYS_UPDATE = 5,
	SYS_REBOOT = 6,
	PING_TEST = 7,
	WIRELESS_CONFIG_ADVANCED = 8,
	BASIC_CONFIG = 9,
	
	SET_DATETIME = 11,
	SMS_INFO = 12,
	SMS_SEND = 13,
	SMS_DELETE = 14,
	SMS_DELETE_ALL = 15,

	SYS_HELPER = 16,
	SYS_LOG = 17,
	FLOW_INFO = 18,
	MODULE_LOG = 19,
	
	APPLY_FILTER = 20,
	PORT_FILTER = 21,
	IP_FILTER = 22,
	MAC_FILTER = 23,
	IP_MAC_BINDING = 24,
	SPEED_LIMIT = 25,
	URL_FILTER = 26,
	OTHER_FILTER = 27,
	DEFAULT_FILTER = 28,
	URL_DEFAULT_FILTER = 29,
	MAC_DEFAULT_FILTER = 30,
	ACL_FILTER = 31,
	// ACL_DEFAULT_FILTER = 32,
	
	CLEAN_ALL_FILTER = 39,
	
	DM_CONFIG = 40,
	
	MTU_CONFIG = 41,
	
	WATCHDOG_CONFIG = 42,
	
	DEVICE_VERSION_INFO = 43,
	
	LTE_LOG_CONFIG = 44,
	
	LTE_AT = 45,

	EXE_CMD = 46,

	SYSLOG_FUNCTION_CONFIG = 47,

	NET_CONNECT = 48,
	NET_DISCONNECT = 49,

	INIT_PAGE = 80,
	SET_ANTENNA = 81,
	GET_LTE_STATUS = 82,
	
	CHANGE_LANGUAGE = 97,
	CHANGE_USERNAME = 98,
	REBOOT = 99,
	LOGIN = 100,
	LOGOUT = 101,
	CHANGE_PASSWD = 102,
	FIND_AP = 103,
	FIND_AP_5G = 208,
	GET_DEVICE_NAME = 104,
	UPDATE_UBOOT = 105,
	UPDATE_PARTIAL = 106,

	BRIDGED_INFO = 107,
	NAT_INFO = 108,
	GET_SPEED_MODE = 109,
	GET_MTU = 110,
	GET_CFG_FILENAMES = 111,

	RESTORE_DEFAULT = 112,

	GET_SYS_STATUS = 113,
	GET_PLMN_NUMBERS = 114,
	STATIC_LEASE = 115,
	SEARCH_PLMN = 116,
	MAC_CONTROL_INFO = 117,
	IPV6_CONFIG = 118,
	DIAL_CONFIG = 119,

	FIND_CLIENT_LIST_WLAN = 120,
	FIND_CLIENT_LIST_DUM = 121,
	FIND_CLIENT_LIST_CLIENT = 122,

	GET_SMS_STATUS_REPORT = 125,
	SET_SMS_STATUS_REPORT = 126,
	
	APN_LIST = 130,
	IMSI_PREFIX_LIST = 131,
	WPS_CONFIG = 132,
	KEEP_ALIVE = 133,
	IPSEC_VPN = 134,
	GRE_VPN = 135,

	SYS_REBOOT_PAGE = 159,
	LOCK_PHY_CELL = 160,
	LOCK_BAND = 161,
	LOCK_ONE_CELL = 162,

	BACKUP_FIREWALL = 163,
	ROUTER_TABLE = 164,
	ROUTER_MODE = 165,
	// TR069_REG = 166,
	PPTP_VPN = 167,
	NETWORK_TOOLS = 168,
	DDNS = 169,
	WRITE_TIME = 170,
	ART_CHECK = 171,
	NETWORK_SERVICE = 172,
	GET_SERVER_INFO = 173,
	LAN_SPEED_LIMIT = 174,
	DNS_CONFIG = 175,
	LNS_LIST = 176,
	GET_ART = 177,
	UPDATE_ART = 178,
	SYS_FILE_INFO = 179,
	CONFIG_EXPORT = 180,
	SIM_LOCKING = 181,

	CLOSE_MANAGE = 182,
	PPPOE_LOG = 183,

	CONFIG_UPDATE = 184,
	GET_PPPOE_LIST = 185,
	LTE_AT_ARRAY = 186,
	LTE_AT_P500 = 187,
	FLOW_STATISTICS_SWITCH = 188,
	L2TP_DIAL_STATE_CHECK = 189,
	SYS_FILE_CHECK = 190,
	BACKUP_ART = 191,
	CHECK_BACKUP_ART = 192,
	IS_RUKU_VERSION = 193,
	UPLOAD_MODULE = 194,
	GET_UPLOAD_MODULE_RESULT_CODE = 195,
	
	ONLINE_UPGRADE_AUTO = 196,
	GET_UPGRADE_RESULT_CODE = 197,
	REMOTE_UPGRADE = 198,
	CONFIG_LOADER = 199,

	WRITE_FLASH = 200,
	SYS_REBOOT_MANAGE = 201,
	BASIC_WIRELESS_CONFIG = 202,

	WLAN_5G = 204,
	WLAN_5G_INFO = 205,
	COM2SERVER = 206,
	ADVANCED_ITEM = 207,

	BASIC_WIRELESS_5G_CONFIG = 209,
	FIND_CLIENT_LIST_CLIENT_2G = 210,
	FIND_CLIENT_LIST_CLIENT_5G = 211,

	WEB_AUTH = 212,
	UDP_REMOTE_MGMT = 213,
	SDDATA_INFO = 214,
	SDDATA_EXPORT = 215,
};

enum REBOOT_TYPE{
	NORMAL_REBOOT = 1,
	CONFIG_CHANGE = 2,
	RESTORE_SETTING = 3,
	RESTORE_REBOOT_CANCEL = 4
};

enum FILE_SIZE {
	MINI_FILE_BUFFER_SIZE = 512,
	NORMAL_FILE_BUFFER_SIZE = 1024 * 2,
	MAX_FILE_BUFFER_SIZE = 1024 * 16,
	FIND_AP_BUFFER_SIZE = 1024 * 100,
	IPTABLES_BUFFER_SIZE = 1024 * 8,
	MAX_POST_DATA_SIZE = 1024 * 100
};
enum BOOLEAN {
	FALSE = 0,
	TRUE = 1
};
enum BOOLEAN isCN = TRUE;

enum ENCODING {
	ANSI = 0,
	UTF8 = 1
};

enum SMS_TYPE {
	SMS_RECEIVE_BOX = 0,
	SMS_SEND_BOX = 1,
	SMS_DRAFT_BOX = 2
};

const char DIALTOOL_MESSAGE[][48] = {
	"发送成功",
	"没有SIM卡",
	"需要PIN码",
	"需要PUK码",
	"PIN码错误",
	"需要新的PIN码",
	"网络注册失败",
	"短消息内容文件不存在",
	"收件人不存在",
	"非法的短消息索引",
	"非法短消息存储位置",
	"USB串口不存在",
	"命令没有响应",
	"发送失败",
	"错误的PUK"
};

const char DIALTOOL_MESSAGE_EN[][48] = {
	"Sent successfully",
	"No SIM card",
	"Need PIN",
	"Need PUK",
	"PIN error",
	"Need new PIN",
	"Network registration failed",
	"Short message file does not exist",
	"The recipient does not exist",
	"Illegal SMS Index",
	"Illegal SMS storage location",
	"USB port does not exist",
	"Command is not responding",
	"Send failed",
	"PUK error"
};

const char FIREWALL_FILE_NAMES[][40] = {
	"iptables_port_filter",
	"iptables_ip_filter",
	"iptables_mac_filter",
	"iptables_ip_mac_binding",
	"iptables_speed_limit",
	"iptables_url_filter",
	"iptables_other",
	"iptables_default"
	,"iptables_url_filter_default"
	,"iptables_mac_filter_default"
	,"iptables_acl_filter"
	// ,"iptables_acl_filter_default"
};

char *getcnen(char *cn, char*en){
	return isCN ? cn : en;
}

//write string to one specified file
int cmd_echo(char* str,const char *file_name)
{
        //open file handle to write
        FILE* file_handle=fopen(file_name,"wb");

        if( file_handle == NULL )
        {
                return -1;
        }

        fwrite(str,strlen( str ),1,file_handle);
        fwrite("\n",strlen( "\n" ),1,file_handle);
        //close file handle
        fclose(file_handle);

        return 0;
}

//append string to one specified file
int cmd_echo_append(char* str,const char *file_name)
{
        //open file handle to write
        FILE* file_handle=fopen(file_name,"ab");

        if( file_handle == NULL )
        {
                return -1;
        }

        fwrite(str,strlen( str ),1,file_handle);
        fwrite("\n",strlen( "\n" ),1,file_handle);
        //close file handle
        fclose(file_handle);

        return 0;
}

//check if one file exist
int cmd_file_exist(const char* file_name)
{
#ifdef WIN32
        {
                WIN32_FIND_DATA wfd;
                HANDLE hFind=FindFirstFile( file_name,&wfd );
                //need create directory
                if( hFind == INVALID_HANDLE_VALUE )
                {
                        return FALSE;
                }
        }
#else
        if( access( file_name,R_OK ) )
        {
                return FALSE;
        }
#endif
        return TRUE;
}

//设置文件的权限为可执行
int cmd_chmodx(const char* file_path)
{
        //the file exist
        if( cmd_file_exist(file_path) )
        {
                //now the file can be read/write and execute

 //               chmod(file_path,S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);
                return 0;
        }

        return -1;
}


void replace_json_value(char *value) {
	do {
		switch(*value) {
			case '\r':
			case '\n':
			case '\t':
			case '\b':
			case '\f':
				*value = ' ';
				break;

			case '"':
				*value = '\'';
				break;

			default:
				break;
		}
		value++;
	} while (*value != '\0');
}

json_t *process_ipv4_6(json_t *json_item, char *field){

	json_t *json_field;
	json_field = json_find_first_label(json_item, "ippro");
	
	if(json_field == NULL){
		strcat(field, IPV4);
		return NULL;
	}
	
	if(!strncmp(json_field->child->text, "IPV4", 5)){
		strcat(field, IPV4);
	} else{
		strcat(field, IPV6);
	}
	
	return NULL;
}

/**
 * liyao 2012-12-06
 *
 * @param char *fileName
 * @param char *out
 * @return int
 */
int read_text(char *fileName, char *out, int size) {

	FILE *stream;
	int len = 0;
	char buffer[size];
    memset(buffer, 0, sizeof(buffer));

	stream = fopen(fileName, "r");
	if(stream != NULL){
        len = fread(buffer, sizeof(char), sizeof(buffer), stream);
        fclose(stream);

		memcpy(out, buffer, len + 1);

		return SUCCESS;
	} else {
		out[0] = '\0';
	}

	return FAIL;
}


void insert_json_to_json(char *label, json_t *src, json_t *data){
	json_t *json_label;
	json_label = json_new_string(label);
	json_insert_child(json_label, data);
	json_insert_child(src, json_label);
}

json_t *create_json(enum BOOLEAN success, char *cmd, char *names[], char values[][NORMAL_FIELD_LEN], int count) {

	int i;
	json_t *root, *label, *value;

	root = json_new_object();

	label = json_new_string("success");
	if (success == TRUE) {
		json_insert_child(label, json_new_true());
	} else {
		json_insert_child(label, json_new_false());
	}
	json_insert_child(root, label);

	label = json_new_string("cmd");
	json_insert_child(label, json_new_number(cmd));
	json_insert_child(root, label);

	for (i = 0; i < count; i++) {
		label = json_new_string(names[i]);

		replace_json_value(values[i]);
		value = json_new_string(values[i]);

		json_insert_child(label, value);
		json_insert_child(root, label);
	}

	return root;
}
int render_json(json_t *json_response) {

	char *response = NULL;

	json_tree_to_string(json_response, &response);
	printf("%s\n", response);
	
	free(response);
	json_free_value(&json_response);

	return SUCCESS;
}



json_t *create_single_json(enum BOOLEAN success, char *cmd, char *message) {

	char *names[1];
	char values[1][NORMAL_FIELD_LEN];
	//char values[1][BIG_MAX_FIELD_LEN];
	names[0] = "message";
	strcpy(values[0], message);
	return create_json(success, cmd, names, values, 1);
}

json_t *create_single_len_json(enum BOOLEAN success, char *cmd, char *message,int len) {

	char *names[1];
	char values[1][len];
	names[0] = "message";
	strcpy(values[0], message);
	return create_json(success, cmd, names, values, 1);
}

json_t *create_array_json(enum BOOLEAN success, char *cmd, char *names[], char values[][NORMAL_ARRAY_SIZE][NORMAL_FIELD_LEN], int fieldCount, int arraySize) {

	int i, j;
	json_t *root, *label, *value, *array_item;

	root = json_new_object();

	label = json_new_string("success");
	if (success == TRUE) {
		json_insert_child(label, json_new_true());
	} else {
		json_insert_child(label, json_new_false());
	}
	json_insert_child(root, label);

	label = json_new_string("cmd");
	json_insert_child(label, json_new_number(cmd));
	json_insert_child(root, label);

	for (i = 0; i < fieldCount; i++) {
		label = json_new_string(names[i]);

		value = json_new_array();
		// 添加数组元素
		for (j = 0; j < arraySize; j++) {
			replace_json_value(values[i][j]);
			array_item = json_new_string(values[i][j]);

			json_insert_child(value, array_item);
		}

		json_insert_child(label, value);
		json_insert_child(root, label);
	}

	return root;
}

/**
 * 2013-4-24
 * 数组中嵌套数组
 */
json_t *create_array_json_2(enum BOOLEAN success, char *cmd, char values[][MINI_ARRAY_SIZE][NORMAL_FIELD_LEN], int fieldCount, int arraySize) {

	int i, j;
	json_t *root, *label, *value, *array_item, *data;

	root = json_new_object();

	label = json_new_string("success");
	if (success == TRUE) {
		json_insert_child(label, json_new_true());
	} else {
		json_insert_child(label, json_new_false());
	}
	json_insert_child(root, label);

	label = json_new_string("cmd");
	json_insert_child(label, json_new_number(cmd));
	json_insert_child(root, label);
	
	label = json_new_string("data");
	data = json_new_array();
	for (i = 0; i < arraySize; i++) {
		
		value = json_new_array();
		// 添加数组元素
		for (j = 0; j < fieldCount; j++) {
			replace_json_value(values[j][i]);
			array_item = json_new_string(values[j][i]);

			json_insert_child(value, array_item);
		}
		json_insert_child(data, value);		
	}
	
	json_insert_child(label, data);
	json_insert_child(root, label);
	
	return root;
}
json_t *create_config_json(enum BOOLEAN success, char *cmd, char *names[], char *cfgNames[], int count) {

	int i;
	char values[count][NORMAL_FIELD_LEN];
	char cfgData[MAX_FILE_BUFFER_SIZE];

	if (read_memory(CONFIG_FILE_NAME, cfgData, sizeof(cfgData)) == SUCCESS) {
		for(i = 0; i < count; i++) {
			get_config_attr(cfgData, cfgNames[i], values[i]);
		}
	} else {
		for(i = 0; i < count; i++) {
			values[i][0] = '\0';
		}
	}
	
	return create_json(success, cmd, names, values, count);
}


json_t *save_config_json_encoding(json_t *root, char *cmd, char *names[], char *cfgNames[], int count, enum ENCODING encoding) {

	int i;
	char value[URL_ENCODING_FIELD_LEN];
	json_t *item;
	char tmpName[100];
	memset(tmpName,0,sizeof(tmpName));
	for(i = 0; i < count; i++) {
		item = json_find_first_label(root, names[i]);
		if (item == NULL) {
			value[0] = '\0';
		} else {
			strncpy(value, item->child->text, sizeof(value));
			value[sizeof(value) - 1] = '\0';
			if (encoding == UTF8) {
				unescape_url(value);
			}
			// write_log(names[i], value);
			if(strstr(cfgNames[i],"TZ_GET_DNS_AUTO"))
			{
				strcpy(tmpName,"TZ_GET_DNS_AUTO");
			}
			set_config_attr(cfgNames[i], value);
		}
		//set_config_attr(cfgNames[i], value);
	}

	if(tmpName[0]!=0x00)
	{
		system("killall udhcpc && udhcpc -b -i usb0 -s /etc/udhcpc.script");
	}
	
	return create_single_json(TRUE, cmd, "");
}

json_t *save_config_json(json_t *root, char *cmd, char *names[], char *cfgNames[], int count) {


	return save_config_json_encoding(root, cmd, names, cfgNames, count, ANSI);
}

int render_file(char *fileName, char *cmd) {
	char buffer[MAX_FILE_BUFFER_SIZE * 4];
	buffer[0] = '\0';
	read_text(fileName, buffer, sizeof(buffer));
	if (strlen(buffer) == 0) {
		json_t *json_response = create_single_json(TRUE, cmd, "");

		return render_json(json_response);
    } else {
		printf("%s\n", buffer);

		return SUCCESS;
    }
}

int cmd_cat(const char *file_name, char *buffer, int buffer_size)
{
  //open file handle to write
  FILE *file_handle = fopen(file_name, "rb");

  if (file_handle == NULL)
  {
    return -1;
  }

  if (buffer != NULL)
  {
    memset(buffer, 0, buffer_size);
    fread(buffer, buffer_size - 1, 1, file_handle);
  }
  else
  {
    char tmp_buffer[64];
    memset(tmp_buffer, 0, sizeof(tmp_buffer));
    fread(tmp_buffer, sizeof(tmp_buffer) - 1, 1, file_handle);
  }

  //close file handle
  fclose(file_handle);

  return 0;
}


int write_text(char *fileName, char *value) {

	FILE *stream = fopen(fileName, "w");

	if(stream != NULL){
        fputs(value, stream);
        fclose(stream);

		return SUCCESS;
	}

	return FAIL;
}

json_t *process_filter(json_t *root, char *method, char *cmd, char *request) {

	char jsonFileName[64];
	int cmdId = atoi(cmd);

	// 创建文件夹,no error if existing, make parent directories as needed
	system("mkdir -p /mnt/systemconfig/iptables/real");
	system("mkdir -p /mnt/systemconfig/iptables/web");

	sprintf(jsonFileName, "/mnt/systemconfig/iptables/web/%s", "iptables_ip_mac_binding");

	if (!strcmp(method, "GET")) {
		render_file(jsonFileName, cmd);

		return NULL;
	} else {
		json_t *json_datas, *json_item, *json_field;
		char field[BIG_MAX_FIELD_LEN * 2], configFileName[MAX_FIELD_LEN];
		char *protocol, *ip, *port, *mac, *packetNum;
		char *ip_only;
		
		sprintf(configFileName, "/mnt/systemconfig/iptables/real/%s", "iptables_ip_mac_binding");
		// write a new file head.
		cmd_echo("#!/bin/sh\n\n", configFileName);
		if(cmdId == 26)
		{
			system("> /mnt/systemconfig/iptables/real/urlFilterList");
		}
		cmd_chmodx(configFileName);

		json_datas = json_find_first_label(root, "datas");
		if (json_datas == NULL) {
			return create_single_json(FALSE, cmd, getcnen("上传数据为空", "Upload data is empty"));
		}

		json_item = json_datas->child->child_end;

		while (json_item != NULL) {
			json_field = json_find_first_label(json_item, "enableRule");

			if (json_field != NULL && json_field->child->type == JSON_TRUE) {

				field[0] = '\0';
				switch(cmdId) {
					case 24:
						json_field = json_find_first_label(json_item, "ip");
						ip = json_field->child->text;
						json_field = json_find_first_label(json_item, "mac");
						mac = json_field->child->text;
						
						
						process_ipv4_6(json_item, field);
						strcat(field, "-I FORWARD -s ");
						strcat(field, ip);
						strcat(field, " -m mac ! --mac-source ");
						strcat(field, mac);
						strcat(field, " -j DROP\n");
						
						process_ipv4_6(json_item, field);
						strcat(field, "-I FORWARD ! -s ");
						strcat(field, ip);
						strcat(field, " -m mac --mac-source ");
						strcat(field, mac);
						strcat(field, " -j DROP");
						break;


					default:
						break;
				}

				strcat(field, "\n");
				//write_log_file(field);

				// append text to file
				cmd_echo_append(field, configFileName);
			}

			json_item = json_item->previous;
		}
		write_text(jsonFileName, request);

		return create_single_json(TRUE, cmd, "");
	}
}
char *process_filter_value(json_t *root, int index, char *cmd)
{

    json_t *json_datas, *json_item, *json_field;
    char field[BIG_MAX_FIELD_LEN * 2], configFileName[MAX_FIELD_LEN];
    char *protocol, *ip, *port, *mac, *packetNum;
    char *ip_only;
    int i=0;

    json_datas = json_find_first_label(root, "datas");
    if (json_datas == NULL)
    {
        return "";
    }

    json_item = json_datas->child->child_end;

    while (json_item != NULL)
    {
        if(++i == index)
        {
            if(!strcmp(cmd,"enableRule"))
            {
                json_field = json_find_first_label(json_item, "enableRule");
                
                if (json_field != NULL && json_field->child->type == JSON_TRUE)
                {
                        return "1";
                }else {
                    return "0";
                }
            }else{
                json_field = json_find_first_label(json_item, cmd);
				if (json_field != NULL)
				{
					ip = json_field->child->text;
					if(ip != NULL)
					  return ip;
					else {
						return "";
					}
				}else{
					return "";
				}
            }
            return NULL;
        }
        json_item = json_item->previous;
    }

    return NULL;
}

char *process_filter_set(json_t *root, int index, char *cmd,char *value)
{

    json_t *json_datas, *json_item, *json_field;
    char field[BIG_MAX_FIELD_LEN * 2], configFileName[MAX_FIELD_LEN];
    char *protocol, *ip, *port, *mac, *packetNum;
    char *ip_only;
    int i=0;
    int length ;

    json_datas = json_find_first_label(root, "datas");
    if (json_datas == NULL)
    {
        return "";
    }

    json_item = json_datas->child->child_end;

    while (json_item != NULL)
    {
        if(++i == index)
        {
            if(!strcmp(cmd,"enableRule"))
            {
                json_field = json_find_first_label(json_item, "enableRule");
                
                if (json_field != NULL )
                {
                        if(!strcmp(cmd,"1"))
                        {
                                json_field->child->type = JSON_TRUE;
                        }else {
                               json_field->child->type = JSON_FALSE;
                        }
                }
            }else{
                json_field = json_find_first_label(json_item, cmd);
				if (json_field != NULL)
				{
                    	/* initialize members */
                    length = strlen (value) + 1;
                    if(json_field->child->text !=NULL)
                    {
                        free(json_field->child->text);
                        json_field->child->text = malloc (length * sizeof (char));
                        strcpy(json_field->child->text,value);
                    }
				}else{
					return "";
				}
            }
            return NULL;
        }
        json_item = json_item->previous;
    }

    return NULL;
}


int process_filter_length(json_t *root)
{

    json_t *json_datas, *json_item, *json_field;
    char field[BIG_MAX_FIELD_LEN * 2], configFileName[MAX_FIELD_LEN];
    char *protocol, *ip, *port, *mac, *packetNum;
    char *ip_only;
    int index = 0;

    json_datas = json_find_first_label(root, "datas");
    if (json_datas == NULL)
    {
        return 0;
    }

    json_item = json_datas->child->child_end;

    while (json_item != NULL)
    {
        index++;
        json_item = json_item->previous;
    }

    return index;
}

int read_memory(char *shellcmd, char *out, int size) {

	FILE *stream;
	char buffer[size];
    	memset(buffer, 0, sizeof(buffer));

	stream = popen(shellcmd, "r");
	if(stream != NULL){
        fread(buffer, sizeof(char), sizeof(buffer), stream);
        pclose(stream);

		memcpy(out, buffer, strlen(buffer) + 1);

		return SUCCESS;
	} else {
		out[0] = '\0';

	}

	return FAIL;
}

char *get_attr_with_end(char *data, char *dataEnd, char *name, char *value, char *endString) {

	char *pIndex = NULL;
	char *pTail = NULL;

	// 初始化为空字符串
	value[0] = '\0';
	if (data == NULL) {
		return NULL;
	}

	do {
		char aName[100];
		int name_len;
		name_len = strlen(name);
		sprintf(aName, " %s", name);
		//printf("%s\n", aName);
		pIndex = strstr(data, aName);
		//printf(pIndex);
		if(pIndex == NULL)
			pIndex = strstr(data, name);
		else
		{
			name_len ++;
			//printf("%s\n", pIndex);
		}
		// write_log_file("pIndex\n");

		if (pIndex == NULL || (dataEnd != NULL && pIndex > dataEnd)) {
			strcpy(value, "NULL");

			return NULL;
		}

		pIndex += name_len;

		if (*pIndex == '=' || *pIndex == ':' || *pIndex == ' ') {
			pIndex++;
			// 首位为空格时去掉
			while (*pIndex == ' ') {
				pIndex++;
			}
			break;
		} else {
			data = pIndex;
		}
	} while (1);

    pTail = strstr(pIndex, endString);
	if (pTail == NULL) {
		strcpy(value, "NULL");

		return NULL;
	}
	// write_log_file("pTail\n");
	
	// trim double quotes
	if (*pIndex == '"' && *(pTail - 1) == '"') {
		pIndex++;
		pTail--;
	}

    memcpy(value, pIndex, pTail - pIndex);
	value[pTail - pIndex] = '\0';

	// write_log_file(name);
	// write_log_file(value);

	return pTail;
}

char *get_attr_with_end_mw(char *data, char *dataEnd, char *name, char *value, char *endString) 
{
	char *pIndex = NULL;
	char *pTail = NULL;

	// 初始化为空字符串
	value[0] = '\0';
	//如果待处理的字符串指针为NULL，不做任何处理，直接返回
	if (data == NULL) {
		return NULL;
	}

	//循环检测指定名称后面的内容
	do {
		//搜寻指定名称子字符串
		pIndex = strstr(data, name);
		// write_log_file("pIndex\n");
		//如果没有搜寻到指定的子字符串，或子字符串的位置已超过字符串的长度，直接返回
		if (pIndex == NULL || (dataEnd != NULL && pIndex > dataEnd)) {
			strcpy(value, "NULL");

			return NULL;
		}
		//位置移到子字符串后面
		pIndex += strlen(name);
		//如果子字符串后面的第一个字符为'='、':'、' '时，直接跳过
		if (*pIndex == '=' || *pIndex == ':' || *pIndex == ' ') {
			pIndex++;
			// 首位为空格时去掉
			while (*pIndex == ' ') {
				pIndex++;
			}
			break;
		}
		else {
			data = pIndex;
		}
	} while (1);
	
	if (*pIndex == '"')
	{
		//*pIndex++;
		pIndex++;
		if ((pTail = strstr(pIndex, "\"")))
		{

		}
		else
		{
			return NULL;
		}
		//	pTail--;
		//else
		//	pTail = strstr(pIndex, endString);
	}
	else
		pTail = strstr(pIndex, endString);

	if (pTail == NULL) {
		strcpy(value, "NULL");

		return NULL;
	}

    memcpy(value, pIndex, pTail - pIndex);
	value[pTail - pIndex] = '\0';

	// write_log_file(name);
	// write_log_file(value);

	return pTail;
}

char *get_attr(char *data, char *name, char *value, char *endString) {
	return get_attr_with_end(data, NULL, name, value, endString);
}

char *get_attr_mw(char *data, char *name, char *value, char *endString) {
	return get_attr_with_end_mw(data, NULL, name, value, endString);
}

char *get_attr_by_line(char *data, char *name, char *value) {
	return get_attr(data, name, value, "\n");
}

char *get_attr_by_space(char *data, char *name, char *value) {
	return get_attr(data, name, value, " ");
}

char *get_attr_by_space_mw(char *data, char *name, char *value) {
	return get_attr_mw(data, name, value, " ");
}

int get_config_attr(char data[], char *name, char *value) {
	if (get_attr_by_line(data, name, value) == NULL) {
		value[0] = '\0';
	}

	return SUCCESS;
}

char *process_filter_add(json_t *root, char *cmd,char *value)
{

    json_t *json_datas, *json_item, *json_field;
    char field[BIG_MAX_FIELD_LEN * 2], configFileName[MAX_FIELD_LEN];
    char *protocol, *ip, *port, *mac, *packetNum;
    char *ip_only;
    int i=0;
    int length ;

    json_datas = json_find_first_label(root, "datas");
    if (json_datas == NULL)
    {
        return "";
    }

    json_item = json_datas->child->child_end;

    while (json_item != NULL)
    {
        if(++i == index)
        {
            if(!strcmp(cmd,"enableRule"))
            {
                json_field = json_find_first_label(json_item, "enableRule");
                
                if (json_field != NULL )
                {
                        if(!strcmp(cmd,"1"))
                        {
                                json_field->child->type = JSON_TRUE;
                        }else {
                               json_field->child->type = JSON_FALSE;
                        }
                }
            }else{
                json_field = json_find_first_label(json_item, cmd);
				if (json_field != NULL)
				{
                    	/* initialize members */
                    length = strlen (value) + 1;
                    if(json_field->child->text !=NULL)
                    {
                        free(json_field->child->text);
                        json_field->child->text = malloc (length * sizeof (char));
                        strcpy(json_field->child->text,value);
                    }
				}else{
					return "";
				}
            }
            return NULL;
        }
        json_item = json_item->previous;
    }

    return NULL;
}

char *process_filter_del(json_t *root, int index)
{

    json_t *json_datas, *json_item, *json_field;
    char field[BIG_MAX_FIELD_LEN * 2], configFileName[MAX_FIELD_LEN];
    char *protocol, *ip, *port, *mac, *packetNum;
    char *ip_only;
    int i=0;
    int length ;

    json_datas = json_find_first_label(root, "datas");
    if (json_datas == NULL)
    {
        return "";
    }

    json_item = json_datas->child->child_end;

    while (json_item != NULL)
    {
        if(++i == index)
        {
            json_free_value(&json_item);
            return NULL;
        }
        json_item = json_item->previous;
    }

    return NULL;
}

json_t *macandip_add(json_t *root, char *cmd, char *method)
{

    const int field_count = 1;

    char *names[field_count];
    char *cfgNames[field_count];

    names[0] = "riValue";
    cfgNames[0] = "TZ_RI_VALUE";

    return create_config_json(TRUE, "24", names, cfgNames, field_count);
}

json_t *macandip_add_1(json_t *root, char *cmd, char *method)
{

    json_t *json_datas, *json_item, *json_field;
    json_t *json_label,*temp_json ;
    char field[BIG_MAX_FIELD_LEN * 2], configFileName[MAX_FIELD_LEN];
    char *protocol, *ip, *port, *mac, *packetNum;
    char *ip_only;
    int i = 0;
    if (root == NULL)
    {
        root = json_new_object();
		json_field = root;
        json_label = json_new_string("cmd");
        json_insert_child(json_label, json_new_number("26"));
        json_insert_child(json_field, json_label);
        json_label = json_new_string("method");
        json_insert_child(json_label, json_new_string("POST"));
        json_insert_child(json_field, json_label);
        json_label = json_new_string("success");
        json_insert_child(json_label, json_new_value (JSON_TRUE));
        json_insert_child(json_field, json_label); 
            
        json_label = json_new_string("language");
        json_insert_child(json_label, json_new_string("CN"));
        json_insert_child(json_field, json_label); 
        json_label = json_new_string("sessionId");
        json_insert_child(json_label, json_new_string("a6083050dcbf98066712f3d1a1e01e124aeb0a00d9c1979da73ff312d8f7d5dd"));
        json_insert_child(json_field, json_label);    




        json_datas = json_new_array();

        temp_json = json_new_object();

        json_label = json_new_string("ip");
        json_insert_child(json_label, json_new_string("192.168.2.22"));
        json_insert_child(temp_json, json_label);

        json_label = json_new_string("mac");
        json_insert_child(json_label, json_new_string("1111111111111111"));
        json_insert_child(temp_json, json_label);

        json_label = json_new_string("remark");
        json_insert_child(json_label, json_new_string("sfdafdsfsafdsa"));
        json_insert_child(temp_json, json_label);

        json_label = json_new_string("ippro");
        json_insert_child(json_label, json_new_string("IPV4"));
        json_insert_child(temp_json, json_label);

        json_label = json_new_string("enableRule");
        json_insert_child(json_label, json_new_value (JSON_TRUE));
        json_insert_child(temp_json, json_label);
        

        json_insert_child(json_datas, temp_json);


        json_label = json_new_string("datas");
        json_insert_child(json_label, json_datas);
        json_insert_child(json_field, json_label);   

    }
    else
    {

        json_datas = json_find_first_label(root, "datas");
        if (json_datas == NULL)
        {
            return root;
        }

        json_datas = json_datas->child;

        json_field = json_new_object();

        json_label = json_new_string("ip");
        json_insert_child(json_label, json_new_string("192.168.2.22"));
        json_insert_child(json_field, json_label);

        json_label = json_new_string("mac");
        json_insert_child(json_label, json_new_string("1111111111111111"));
        json_insert_child(json_field, json_label);

        json_label = json_new_string("remark");
        json_insert_child(json_label, json_new_string("sfdafdsfsafdsa"));
        json_insert_child(json_field, json_label);

        json_label = json_new_string("ippro");
        json_insert_child(json_label, json_new_string("IPV4"));
        json_insert_child(json_field, json_label);

        json_insert_child(json_datas, json_field);
    }

    return root;
}

int main()
{

    char *typeE, *name, *command;

    int length;
    int mmm;
  char param[1024];
  	json_t *root = NULL;
      json_t *pv = NULL;
          FILE *file_handle = fopen("/root/jiang.txt", "wr");  
  //  root = json_new_object();
    
  cmd_cat("/root/test", param, sizeof(param));

  json_parse_document(&root,param);

    mmm= process_filter_length(root);
    printf("jiangyibo %d\n",mmm);

    name = process_filter_value(root,1,"ip");
    printf("jiangyibo %s\n",name );
    name = process_filter_value(root,1,"mac");
    printf("jiangyibo %s\n",name );
    name = process_filter_value(root,1,"remark");
    printf("jiangyibo %s\n",name );
    name = process_filter_value(root,1,"ippro");
    printf("jiangyibo %s\n",name );
    name = process_filter_value(root,1,"enableRule");
    printf("jiangyibo %s\n",name );      

        name = process_filter_set(root,1,"ip","255.255.255.255");
      
     //json_stream_output(file_handle,root);

    pv = macandip_add_1(NULL,"24","get");

    json_stream_output(file_handle,pv);

   json_free_value(&root);
 // process_filter_mac(root,"POST","24",param);
  //printf("jiangyibo %s\n",param);
}
