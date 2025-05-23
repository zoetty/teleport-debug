# session-bind失敗時の再現方法(Japanese)

## 環境構築

### Windows環境の用意

1. Windows 11 24H2以降の端末を用意する
2. 管理者権限でPowerShellを起動する
3. 下記コマンドを実行しOpenSSH for Windowsをインストールする
    - `Add-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0"`
    - ` Add-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0"`
3. `Stop-Service ssh-agent`を実行

### teleportの準備

1. 適当なteleportクラスターを構築・準備する
    - 特殊な設定は不要

### 非teleportノードの準備
1. OpenSSH Server 8.9以降が起動するLinuxサーバを起動する
    - ex. Ubuntu 22.04等
2. teleportのCA証明書でSSHログイン可能なように、`sshd_config`に`TrustedUserCAKeys`を設定する

### docker-coposeで環境構築する場合

[docker-compose.yml](docker-compose.yml)を利用することで以下を構築可能です。
- teleportクラスター
- teleportノード
  - teleport発行の証明書でログイン可能なOpenSSH Server入り

docker-composeを利用する場合は、用意したWindows端末で以下を実行してください。
1. Docker Desktop for Windowsをインストールする
2. [docker-compose.yml](docker-compose.yml)の存在するディレクトリで`docker-compose up`を実行する
3. 下記コマンドを実行しteleportユーザを作成する
  - `docker exec -ti teleport-debug tctl users add admin --roles=editor,access --logins=root`
  - 生成されたURLにアクセスし適宜Password/MFAの設定をしてください

## 再現手順

docker-compose.ymlを利用してteleportクラスターを構築した場合としています。
teleportクラスターを別途用意している場合はユーザ名等適宜読み替えてください。

1. PowerShellを起動し、検証用teleportクラスターにログインを行う
  - eg.) `tsh login --insecure --proxy localhost --auth local --user admin`
2. 別のPowerShellを管理者権限で起動し、`ssh-agent -dd`を実行する
3. 用意したteleportノードに、`tsh -A --add-keys-to-agent=no root@teleport-debug`で接続を行う
    - `-A`と`--add-keys-to-agent=no`がポイント
4. 接続先で`ssh -A localhost`を2回実行する

`ssh-agent`を起動したターミナルログより、`process_ext_session_bind`の2回目の処理で失敗し、プロセスが終了していることが確認出来る

```
PS C:\Windows\system32> ssh-agent -dd
agent_start pid:10292, dbg:1
client pid 2680 connected
agent_process_connection pipe:0000000000000194
debug1: get_con_client_info: sshagent_con_username: alice
debug1: client type: restricted user
debug1: process agent request type 27
debug2: process_extension: entering
debug2: process_ext_session_bind: entering
debug1: process_ext_session_bind: recorded ED25519 SHA256:Oa1cDtXWFea0Cr3t8fzH4NyrvXXLgrV7ieHuotQOJP8 (slot 0 of 16)
debug1: process agent request type 11
debug1: process agent request type 27
debug2: process_extension: entering
debug2: process_ext_session_bind: entering
process_ext_session_bind: attempt to bind session ID to socket previously bound for authentication attempt
debug1: connection 000001F7EF6968D0 clean up
debug1: iocp error: 6 on 0000000000000000
```


## ssh-agentのオフィシャル版とWindows版の実装差異

### openssh-portable (オフィシャル版)

session-bindリクエストを処理する流れは以下の通り。

1. `session-bind@openssh.com`は[process_ext_session_bind](https://github.com/openssh/openssh-portable/blob/73ef0563a59f90324f8426c017f38e20341b555f/ssh-agent.c#L1703-L1788)で処理が行われる
    - `process_ext_session_bind`は処理結果に応じて戻り値を返す
```C
static int
process_ext_session_bind(SocketEntry *e)
{
	int r, sid_match, key_match;
	struct sshkey *key = NULL;

// snip

	sshbuf_free(sid);
	sshbuf_free(sig);
	return r == 0 ? 1 : 0;
}
```

2. `process_ext_session_bind`は[process_extension](https://github.com/openssh/openssh-portable/blob/73ef0563a59f90324f8426c017f38e20341b555f/ssh-agent.c#L1802)から呼び出されている
    - `process_extension`は`process_ext_session_bind`の戻り値をSSHクライアントに返送する
    - 関数としての戻り値は無い

```C
static void
process_extension(SocketEntry *e)
{
	int r, success = 0;
	char *name;


	debug2_f("entering");
	if ((r = sshbuf_get_cstring(e->request, &name, NULL)) != 0) {
		error_fr(r, "parse");
		goto send;
	}
	if (strcmp(name, "session-bind@openssh.com") == 0)
		success = process_ext_session_bind(e);
	else
		debug_f("unsupported extension \"%s\"", name);
	free(name);
send:
	send_status(e, success);
}
```

3. `process_extension`は[process_message](https://github.com/openssh/openssh-portable/blob/73ef0563a59f90324f8426c017f38e20341b555f/ssh-agent.c#L1901-L1911)から呼び出されている
    - `process_message`は`process_extension`の実行結果にかかわらず[1](https://github.com/openssh/openssh-portable/blob/73ef0563a59f90324f8426c017f38e20341b555f/ssh-agent.c#L1911)を返す

```C
static int
process_message(u_int socknum)
{
	u_int msg_len;
	u_char type;

// snip

	case SSH_AGENTC_EXTENSION:
		process_extension(e);
		break;
	default:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		break;
	}
	return 1;
}
```

4. 結果、`session-bind@openssh.com`の処理結果に関わらず、`process_message`は正常処理扱いとなり、`ssh-agent`プロセスは継続する


### openssh-portable(Windows版)

基本的な処理の流れはオフィシャル版と同じであるが、`process_ext_session_bind`の処理結果が`process_request`の戻り値として伝搬される点が異なる。

1. [process_extension](https://github.com/PowerShell/openssh-portable/blob/latestw_all/contrib/win32/win32compat/ssh-agent/keyagent-request.c#L1023-L1047)は、`process_ext_session_bind`の戻り値を元に、戻り値を決定している

```C
int
process_extension(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con)
{
	int r, success = 0;
	char *name;


	debug2_f("entering");
	if ((r = sshbuf_get_cstring(request, &name, NULL)) != 0) {
		error_fr(r, "parse");
		goto send;
	}
	if (strcmp(name, "session-bind@openssh.com") == 0)
		success = process_ext_session_bind(request, con);
	else
		debug_f("unsupported extension \"%s\"", name);
	free(name);
send:
	if ((r = sshbuf_put_u32(response, 1) != 0) ||
		((r = sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE)) != 0))
		fatal_fr(r, "compose");


	r = success ? 0 : -1;
	
	return r;
}
```
2. [process_request](https://github.com/PowerShell/openssh-portable/blob/bdacf9868fe9e8024a5312861b7aaa6faba1821f/contrib/win32/win32compat/ssh-agent/connection.c#L170-L196)は`process_extension`の戻り値を呼び出し元に返す

```C
static int
process_request(struct agent_connection* con) 
{
// snip
	case SSH_AGENTC_EXTENSION:
		r = process_extension(request, response, con);
		break;
	default:
		debug("unknown agent request %d", type);
		r = -1;
		break;
	}


done:
	if (request)
		sshbuf_free(request);


	ZeroMemory(&con->io_buf, sizeof(con->io_buf));
	if (r == 0) {
		POKE_U32(con->io_buf.buf, (u_int32_t)sshbuf_len(response));
		if ((err = memcpy_s(con->io_buf.buf + 4, sizeof(con->io_buf.buf) - 4, sshbuf_ptr(response), sshbuf_len(response))) != 0) {
			debug("memcpy_s failed with error: %d.", err);
			r = -1;
		}
		con->io_buf.num_bytes = (DWORD)sshbuf_len(response) + 4;
	}
	
	if (response)
		sshbuf_free(response);


	return r;
```

3. `process_request`の呼び出し元である[agent_connection_on_io](https://github.com/PowerShell/openssh-portable/blob/bdacf9868fe9e8024a5312861b7aaa6faba1821f/contrib/win32/win32compat/ssh-agent/connection.c#L51-L111)では、`process_request`が`0`以外を返したとき、接続をクローズしプロセスを終了させる

```C
			if (process_request(con) != 0) {
				ABORT_CONNECTION_RETURN(con);
			}
```

## Windows版ssh-agentとsshクライアントで問題が出ない理由

sshクライアントの実装は、OS固有の機能に合わせた移植以外はオフィシャル版とWindows版で大きな違いはありません。

sshクライアントは、`ssh-agent`へのリクエストを実行する際に、都度通信チャンネルを開きます。

- WindowsならNamedPipe
- *nixならUnix Domain Socket

一例として、`ssh-add -l`相当のリクエストが処理される部分を抜粋します。
処理としては、`get_agent_identities` -> `get_agent_authentication_socket` -> `get_agent_authentication_socket_path`と呼び出され、都度`socket`/`connect`を呼び出して接続
をしています。

https://github.com/openssh/openssh-portable/blob/73ef0563a59f90324f8426c017f38e20341b555f/sshconnect2.c#L1629-L1658

```C
/* obtain a list of keys from the agent */
static int
get_agent_identities(struct ssh *ssh, int *agent_fdp,
    struct ssh_identitylist **idlistp)
{
	int r, agent_fd;
	struct ssh_identitylist *idlist;


	if ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		if (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		return r;
	}
	if ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
	    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
		debug_f("bound agent to hostkey");
	else
		debug2_fr(r, "ssh_agent_bind_hostkey");


	if ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		return r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	return 0;
}
```

https://github.com/openssh/openssh-portable/blob/73ef0563a59f90324f8426c017f38e20341b555f/authfd.c#L121-L134
```C
int
ssh_get_authentication_socket(int *fdp)
{
	const char *authsocket;


	if (fdp != NULL)
		*fdp = -1;


	authsocket = getenv(SSH_AUTHSOCKET_ENV_NAME);
	if (authsocket == NULL || *authsocket == '\0')
		return SSH_ERR_AGENT_NOT_PRESENT;


	return ssh_get_authentication_socket_path(authsocket, fdp);
}
```

https://github.com/openssh/openssh-portable/blob/73ef0563a59f90324f8426c017f38e20341b555f/authfd.c#L89-L115
```C
ssh_get_authentication_socket_path(const char *authsocket, int *fdp)
{
	int sock, oerrno;
	struct sockaddr_un sunaddr;


	debug3_f("path '%s'", authsocket);
	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, authsocket, sizeof(sunaddr.sun_path));


	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return SSH_ERR_SYSTEM_ERROR;


	/* close on exec */
	if (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1 ||
	    connect(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == -1) {
		oerrno = errno;
		close(sock);
		errno = oerrno;
		return SSH_ERR_SYSTEM_ERROR;
	}
	if (fdp != NULL)
		*fdp = sock;
	else
		close(sock);
	return 0;
}
```

このため、何らかの問題で`session-bind@openssh.com`が失敗し`ssh-agent`との接続が失われても、次のエージェントリクエストで再接続されるため問題は表面化しません。
