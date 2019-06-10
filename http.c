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
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <sys/wait.h>

#include <sys/msg.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <pthread.h>
#include "json.h"

#define __WEXITSTATUS(status) (((status)&0xff00) >> 8)
#define WEXITSTATUS(status) __WEXITSTATUS(status)

#define __WTERMSIG(status) ((status)&0x7f)
#define __WIFEXITED(status) (__WTERMSIG(status) == 0)
#define WIFEXITED(status) __WIFEXITED(status)

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

#define TMP_FAIL_LOGIN_TIMES_FILE "/tmp/.login_fail_times"
#define TEMP_DIALTOOL_INDICATOR "/tmp/.dialtool_indicator"
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
#define MAX_FIELD_LEN 256
#define BIG_MAX_FIELD_LEN 1024
#define IPV4 "iptables "
#define IPV6 "ip6tables "

json_t *process_ipv4_6(json_t *json_item, char *field)
{

	json_t *json_field;
	json_field = json_find_first_label(json_item, "ippro");

	if (json_field == NULL)
	{
		strcat(field, IPV4);
		return NULL;
	}

	if (!strncmp(json_field->child->text, "IPV4", 5))
	{
		strcat(field, IPV4);
	}
	else
	{
		strcat(field, IPV6);
	}

	return NULL;
}

int tempacceptAllFlag = 0;
int ebtablesFlag = 0;

void get_cmd_result(char *shellcmd, char *buffer, int size)
{

	FILE *stream;
	memset(buffer, 0, size);

	stream = popen(shellcmd, "r");
	if (stream != NULL)
	{
		fread(buffer, sizeof(char), size - 1, stream);
		pclose(stream);
	}
	else
	{
		buffer[0] = '\0';
	}
}

process_filter(json_t *root, char *method, char *cmd, char *request)
{

	char jsonFileName[64];
	char cmdbuf[128];
	int cmdId = atoi(cmd);

	// 创建文件夹,no error if existing, make parent directories as needed
	system("mkdir -p /mnt/systemconfig/iptables/real");
	system("mkdir -p /mnt/systemconfig/iptables/web");

	sprintf(jsonFileName, "/mnt/systemconfig/iptables/web/%s", "iptables_ip_mac_binding");

	if (!strcmp(method, "GET"))
	{
		//		render_file(jsonFileName, cmd);

		return NULL;
	}
	else
	{
		json_t *json_datas, *json_item, *json_field;
		char field[1024 * 2], configFileName[256];
		char *protocol, *ip, *port, *mac, *packetNum;
		char *ip_only;

		sprintf(configFileName, "/mnt/systemconfig/iptables/real/%s", "iptables_ip_mac_binding");
		// write a new file head.
		cmd_echo("#!/bin/sh\n\n", configFileName);
		if (cmdId == 26)
		{
			system("> /mnt/systemconfig/iptables/real/urlFilterList");
		}
		cmd_chmodx(configFileName);

		json_datas = json_find_first_label(root, "datas");
		if (json_datas == NULL)
		{
			return NULL;
		}

		json_item = json_datas->child->child_end;
		get_cmd_result("cat /version | grep type | sed 's/type://'", cmdbuf, sizeof(cmdbuf));
		if (strncmp(cmdbuf, "tozedap-p59_gx_zfz", strlen("tozedap-p59_gx_zfz")) == 0)
		{
			ebtablesFlag = 1;
		}

		while (json_item != NULL)
		{
			json_field = json_find_first_label(json_item, "enableRule");

			if (json_field != NULL && json_field->child->type == JSON_TRUE)
			{

				field[0] = '\0';
				switch (cmdId)
				{
				case 24:
					json_field = json_find_first_label(json_item, "ip");
					ip = json_field->child->text;
					json_field = json_find_first_label(json_item, "mac");
					mac = json_field->child->text;

					if (1 == tempacceptAllFlag)
					{
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
					}
					else
					{
						process_ipv4_6(json_item, field);
						strcat(field, "-I FORWARD -d ");
						strcat(field, ip);
						strcat(field, " -j ACCEPT\n");

						process_ipv4_6(json_item, field);
						strcat(field, "-I FORWARD -s ");
						strcat(field, ip);
						strcat(field, " -m mac --mac-source ");
						strcat(field, mac);
						strcat(field, " -j ACCEPT\n");
						if (1 <= ebtablesFlag)
						{
							if (1 == ebtablesFlag)
							{
								//        strcat(field, "ebtables -F FORWARD\n");
								strcat(field, "ebtables -A FORWARD -o tap0 -j DROP\n");
								ebtablesFlag++;
							}
							strcat(field, "ebtables -I FORWARD -s ");
							strcat(field, mac);
							strcat(field, " -o tap0 -j ACCEPT\n");
						}
					}

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

		return NULL;
	}
}

char *process_filter_value(json_t *root, int index, char *cmd)
{

	json_t *json_datas, *json_item, *json_field;
	char field[BIG_MAX_FIELD_LEN * 2], configFileName[MAX_FIELD_LEN];
	char *protocol, *ip, *port, *mac, *packetNum;
	char *ip_only;
	int i = 0;

	json_datas = json_find_first_label(root, "datas");
	if (json_datas == NULL)
	{
		return "";
	}

	json_item = json_datas->child->child_end;

	while (json_item != NULL)
	{
		if (++i == index)
		{
			if (!strcmp(cmd, "enableRule"))
			{
				json_field = json_find_first_label(json_item, "enableRule");

				if (json_field != NULL && json_field->child->type == JSON_TRUE)
				{
					return "1";
				}
				else
				{
					return "0";
				}
			}
			else
			{
				json_field = json_find_first_label(json_item, cmd);
				if (json_field != NULL)
				{
					ip = json_field->child->text;
					if (ip != NULL)
						return ip;
					else
					{
						return "";
					}
				}
				else
				{
					return "";
				}
			}
			return NULL;
		}
		json_item = json_item->previous;
	}

	return NULL;
}

char *process_filter_set(json_t *root, int index, char *cmd, char *value)
{

	json_t *json_datas, *json_item, *json_field;
	char field[BIG_MAX_FIELD_LEN * 2], configFileName[MAX_FIELD_LEN];
	char *protocol, *ip, *port, *mac, *packetNum;
	char *ip_only;
	int i = 0;
	int length;

	json_datas = json_find_first_label(root, "datas");
	if (json_datas == NULL)
	{
		return "";
	}

	json_item = json_datas->child->child_end;

	while (json_item != NULL)
	{
		if (++i == index)
		{
			if (!strcmp(cmd, "enableRule"))
			{
				json_field = json_find_first_label(json_item, "enableRule");

				if (json_field != NULL)
				{
					if (!strcmp(cmd, "1"))
					{
						json_field->child->type = JSON_TRUE;
					}
					else
					{
						json_field->child->type = JSON_FALSE;
					}
				}
			}
			else
			{
				json_field = json_find_first_label(json_item, cmd);
				if (json_field != NULL)
				{
					/* initialize members */
					length = strlen(value) + 1;
					if (json_field->child->text != NULL)
					{
						free(json_field->child->text);
						json_field->child->text = malloc(length * sizeof(char));
						strcpy(json_field->child->text, value);
					}
				}
				else
				{
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
	if (root == NULL)
		return 0;

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

char *get_attr_with_end_mw(char *data, char *dataEnd, char *name, char *value, char *endString)
{
	char *pIndex = NULL;
	char *pTail = NULL;

	// 初始化为空字符串
	value[0] = '\0';
	//如果待处理的字符串指针为NULL，不做任何处理，直接返回
	if (data == NULL)
	{
		return NULL;
	}

	//循环检测指定名称后面的内容
	do
	{
		//搜寻指定名称子字符串
		pIndex = strstr(data, name);
		// write_log_file("pIndex\n");
		//如果没有搜寻到指定的子字符串，或子字符串的位置已超过字符串的长度，直接返回
		if (pIndex == NULL || (dataEnd != NULL && pIndex > dataEnd))
		{
			strcpy(value, "NULL");

			return NULL;
		}
		//位置移到子字符串后面
		pIndex += strlen(name);
		//如果子字符串后面的第一个字符为'='、':'、' '时，直接跳过
		if (*pIndex == '=' || *pIndex == ':' || *pIndex == ' ')
		{
			pIndex++;
			// 首位为空格时去掉
			while (*pIndex == ' ')
			{
				pIndex++;
			}
			break;
		}
		else
		{
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

	if (pTail == NULL)
	{
		strcpy(value, "NULL");

		return NULL;
	}

	memcpy(value, pIndex, pTail - pIndex);
	value[pTail - pIndex] = '\0';

	// write_log_file(name);
	// write_log_file(value);

	return pTail;
}

char *process_filter_add(json_t *root, char *cmd, char *value)
{

	json_t *json_datas, *json_item, *json_field;
	char field[BIG_MAX_FIELD_LEN * 2], configFileName[MAX_FIELD_LEN];
	char *protocol, *ip, *port, *mac, *packetNum;
	char *ip_only;
	int i = 0;
	int length;

	json_datas = json_find_first_label(root, "datas");
	if (json_datas == NULL)
	{
		return "";
	}

	json_item = json_datas->child->child_end;

	while (json_item != NULL)
	{
		if (++i == index)
		{
			if (!strcmp(cmd, "enableRule"))
			{
				json_field = json_find_first_label(json_item, "enableRule");

				if (json_field != NULL)
				{
					if (!strcmp(cmd, "1"))
					{
						json_field->child->type = JSON_TRUE;
					}
					else
					{
						json_field->child->type = JSON_FALSE;
					}
				}
			}
			else
			{
				json_field = json_find_first_label(json_item, cmd);
				if (json_field != NULL)
				{
					/* initialize members */
					length = strlen(value) + 1;
					if (json_field->child->text != NULL)
					{
						free(json_field->child->text);
						json_field->child->text = malloc(length * sizeof(char));
						strcpy(json_field->child->text, value);
					}
				}
				else
				{
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
	int i = 0;
	int length;

	json_datas = json_find_first_label(root, "datas");
	if (json_datas == NULL)
	{
		return "";
	}

	json_item = json_datas->child->child_end;

	while (json_item != NULL)
	{
		if (++i == index)
		{
			json_free_value(&json_item);
			return NULL;
		}
		json_item = json_item->previous;
	}

	return NULL;
}

json_t *macandip_add_1(json_t *root, char *cmd, char *method)
{

	json_t *json_datas, *json_item, *json_field, *label;
	json_t *json_label, *temp_json;
	char field[BIG_MAX_FIELD_LEN * 2], configFileName[MAX_FIELD_LEN];
	char *protocol, *ip, *port, *mac, *packetNum;
	char *ip_only;
	int i = 0;
	if (root == NULL)
	{

		root = json_new_object();
		json_label = json_new_string("cmd");
		json_insert_child(json_label, json_new_number("26"));
		json_insert_child(root, json_label);
		json_label = json_new_string("method");
		json_insert_child(json_label, json_new_string("POST"));
		json_insert_child(root, json_label);
		json_label = json_new_string("success");
		json_insert_child(json_label, json_new_value(JSON_TRUE));
		json_insert_child(root, json_label);

		json_label = json_new_string("language");
		json_insert_child(json_label, json_new_string("CN"));
		json_insert_child(root, json_label);
		json_label = json_new_string("sessionId");
		json_insert_child(json_label, json_new_string("a6083050dcbf98066712f3d1a1e01e124aeb0a00d9c1979da73ff312d8f7d5dd"));
		json_insert_child(root, json_label);

		json_datas = json_new_array();

		temp_json = json_new_object();

		json_label = json_new_string("ip");
		json_insert_child(json_label, json_new_string("255.255.255.255"));
		json_insert_child(temp_json, json_label);

		json_label = json_new_string("mac");
		json_insert_child(json_label, json_new_string("11:11:11:11:11:11"));
		json_insert_child(temp_json, json_label);

		json_label = json_new_string("remark");
		json_insert_child(json_label, json_new_string("add device"));
		json_insert_child(temp_json, json_label);

		json_label = json_new_string("ippro");
		json_insert_child(json_label, json_new_string("IPV4"));
		json_insert_child(temp_json, json_label);

		json_label = json_new_string("enableRule");
		json_insert_child(json_label, json_new_value(JSON_TRUE));
		json_insert_child(temp_json, json_label);

		json_insert_child(json_datas, temp_json);

		json_label = json_new_string("datas");
		json_insert_child(json_label, json_datas);
		json_insert_child(root, json_label);
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
		json_insert_child(json_label, json_new_string("255.255.255.255"));
		json_insert_child(json_field, json_label);

		json_label = json_new_string("mac");
		json_insert_child(json_label, json_new_string("11:11:11:11:11:11"));
		json_insert_child(json_field, json_label);

		json_label = json_new_string("remark");
		json_insert_child(json_label, json_new_string("add device"));
		json_insert_child(json_field, json_label);

		json_label = json_new_string("ippro");
		json_insert_child(json_label, json_new_string("IPV4"));
		json_insert_child(json_field, json_label);

		json_label = json_new_string("enableRule");
		json_insert_child(json_label, json_new_value(JSON_TRUE));
		json_insert_child(json_field, json_label);

		json_insert_child(json_datas, json_field);
	}

	return root;
}

//write string to one specified file
int cmd_echo(char *str, const char *file_name)
{
	//open file handle to write
	FILE *file_handle = fopen(file_name, "wb");

	if (file_handle == NULL)
	{
		return -1;
	}

	fwrite(str, strlen(str), 1, file_handle);
	fwrite("\n", strlen("\n"), 1, file_handle);
	//close file handle
	fclose(file_handle);

	return 0;
}

//check if one file exist
int cmd_file_exist(const char *file_name)
{
#ifdef WIN32
	{
		WIN32_FIND_DATA wfd;
		HANDLE hFind = FindFirstFile(file_name, &wfd);
		//need create directory
		if (hFind == INVALID_HANDLE_VALUE)
		{
			return 0;
		}
	}
#else
	if (access(file_name, R_OK))
	{
		return 0;
	}
#endif
	return 1;
}

//设置文件的权限为可执行
int cmd_chmodx(const char *file_path)
{
	//the file exist
	if (cmd_file_exist(file_path))
	{
//now the file can be read/write and execute
#ifndef WIN32
		chmod(file_path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH);
#endif
		return 0;
	}

	return -1;
}

//append string to one specified file
int cmd_echo_append(char *str, const char *file_name)
{
	//open file handle to write
	FILE *file_handle = fopen(file_name, "ab");

	if (file_handle == NULL)
	{
		return -1;
	}

	fwrite(str, strlen(str), 1, file_handle);
	fwrite("\n", strlen("\n"), 1, file_handle);
	//close file handle
	fclose(file_handle);

	return 0;
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

//配置IP地址
int util_config_ipv4_addr(const char *net_dev, const char *ipaddr)
{
	struct ifreq ifr;
	int fd = 0;
	struct sockaddr_in *pAddr;

	if ((NULL == net_dev) || (NULL == ipaddr))
	{
		//dbg_log_print(LOG_ERR, "illegal call function SetGeneralIP!");
		return -1;
	}

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		//dbg_log_print(LOG_ERR,"socket....setip..false!!!");
		return -1;
	}

	strcpy(ifr.ifr_name, net_dev);

	pAddr = (struct sockaddr_in *)&(ifr.ifr_addr);
	bzero(pAddr, sizeof(struct sockaddr_in));
	pAddr->sin_addr.s_addr = inet_addr(ipaddr);
	pAddr->sin_family = AF_INET;
	if (ioctl(fd, SIOCSIFADDR, &ifr) < 0)
	{
		close(fd);
		//dbg_log_print(LOG_ERR,"ioctl..set_ipaddr..false!!!");
		return -1;
	}
	close(fd);
	return 0;
}

int main()
{

	char *typeE, *name, *command, *net_dev, *ipaddr;

	int length;
	int mmm;
	int index;
	char tBuf[32];
	char field[128];
	char configFileName[64];
	char param[1024];
	json_t *root = NULL;
	json_t *pv = NULL;
	FILE *file_handle = fopen("jiang.txt", "wr");
	//  root = json_new_object();
	for (index = 2; index <= 10; index++)
	{
		sprintf(tBuf, "br0:%d", index);
		util_config_ipv4_addr(tBuf, "0.0.0.0");
	}
	cmd_cat("test", param, sizeof(param));

	sprintf(configFileName, "/mnt/systemconfig/mullanip/real/%s", "mullanip");
	// write a new file head.
	cmd_echo("#!/bin/sh\n\n", configFileName);

	cmd_chmodx(configFileName);

	json_parse_document(&root, param);

	mmm = process_filter_length(root);
	printf("jiangyibo leng %d\n", mmm);

	for (index = 1; index <= mmm; index++)
	{
		ipaddr = process_filter_value(root, index, "ip");

		net_dev = process_filter_value(root, index, "interface");


		name = process_filter_value(root, index, "remark");
//		printf("jiangyibo remark %s\n", name);
		name = process_filter_value(root, index, "ippro");
//		printf("jiangyibo ippro %s\n", name);
		name = process_filter_value(root, index, "enableRule");
//		printf("jiangyibo enableRule %s\n", name);
		if (ipaddr != NULL && net_dev != NULL)
		{
			util_config_ipv4_addr(net_dev, ipaddr);
			sprintf(field, "ifconfig %s %s up\n", net_dev, ipaddr);
			cmd_echo_append(field, configFileName);
		}
	}


	//       name = process_filter_set(root,1,"ip","255.255.255.255");

	json_stream_output(file_handle, root);

	//   pv = macandip_add_1(NULL,"24","get");

	//   json_stream_output(file_handle,pv);

	json_stream_output(file_handle, root);

	//   pv = macandip_add_1(NULL,"24","get");

	//   json_stream_output(file_handle,pv);

	json_free_value(&root);
	// process_filter_mac(root,"POST","24",param);
	printf("jiangyibo %s\n", param);
}
