# How to Reproduce session-bind Failure (English)

NOTE: This document was translated by ChatGPT. The original Japanese document is [here](README.ja.md).

## Environment Setup

### Preparing a Windows Environment

1. Prepare a device running Windows 11 24H2 or later.
2. Launch PowerShell with administrator privileges.
3. Execute the following commands to install OpenSSH for Windows:
    - `Add-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0"`
    - `Add-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0"`
4. Run `Stop-Service ssh-agent`.

### Preparing Teleport

1. Set up and prepare a Teleport cluster.
    - No special configuration is required.

### Preparing Non-Teleport Nodes

1. Launch a Linux server running OpenSSH Server 8.9 or later.
    - Example: Ubuntu 22.04, etc.
2. Configure `TrustedUserCAKeys` in `sshd_config` to allow SSH login using Teleport's CA certificate.

### Setting Up the Environment with Docker Compose

Using [docker-compose.yml](docker-compose.yml), you can set up the following:
- Teleport cluster
- Teleport node
  - Includes OpenSSH Server that allows login with certificates issued by Teleport.

If using Docker Compose, execute the following steps on the prepared Windows device:
1. Install Docker Desktop for Windows.
2. Run `docker-compose up` in the directory containing [docker-compose.yml](docker-compose.yml).
3. Execute the following commands to create a Teleport user:
    - `docker exec -ti teleport-debug tctl users add admin --roles=editor,access --logins=root`
    - Access the generated URL and configure Password/MFA as needed.

## Reproduction Steps

Assuming the Teleport cluster is set up using docker-compose.yml. If you have prepared a separate Teleport cluster, adjust usernames and other details accordingly.

1. Launch PowerShell and log in to the test Teleport cluster:
    - Example: `tsh login --insecure --proxy localhost --auth local --user admin`
2. Launch another PowerShell with administrator privileges and execute `ssh-agent -dd`.
3. Connect to the prepared Teleport node using `tsh -A --add-keys-to-agent=no root@teleport-debug`.
    - The key points are `-A` and `--add-keys-to-agent=no`.
4. Execute `ssh -A localhost` twice on the connection target.

From the terminal logs of the `ssh-agent`, you can confirm that the second `process_ext_session_bind` attempt fails, causing the process to terminate.

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

## Implementation Differences Between Official and Windows Versions of ssh-agent

### openssh-portable (Official Version)

The flow for processing session-bind requests is as follows:

1. `session-bind@openssh.com` is processed by [process_ext_session_bind](https://github.com/openssh/openssh-portable/blob/73ef0563a59f90324f8426c017f38e20341b555f/ssh-agent.c#L1703-L1788), which returns a result based on the processing outcome.
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

2. `process_ext_session_bind` is called by [process_extension](https://github.com/openssh/openssh-portable/blob/73ef0563a59f90324f8426c017f38e20341b555f/ssh-agent.c#L1802), which sends the result back to the SSH client.But there is no return value for the function.

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

3. `process_extension` is called by [process_message](https://github.com/openssh/openssh-portable/blob/73ef0563a59f90324f8426c017f38e20341b555f/ssh-agent.c#L1901-L1911), which always returns `1`, regardless of the processing result.

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

4. As a result, the `session-bind@openssh.com` processing outcome does not affect the continuation of the `ssh-agent` process.

### openssh-portable (Windows Version)

The basic flow is similar to the official version, but the processing result of `process_ext_session_bind` propagates to `process_request`.

1. [process_extension](https://github.com/PowerShell/openssh-portable/blob/latestw_all/contrib/win32/win32compat/ssh-agent/keyagent-request.c#L1023-L1047) determines its return value based on the result of `process_ext_session_bind`.

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

2. [process_request](https://github.com/PowerShell/openssh-portable/blob/bdacf9868fe9e8024a5312861b7aaa6faba1821f/contrib/win32/win32compat/ssh-agent/connection.c#L170-L196) returns the result of `process_extension` to its caller.

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

3. [agent_connection_on_io](https://github.com/PowerShell/openssh-portable/blob/bdacf9868fe9e8024a5312861b7aaa6faba1821f/contrib/win32/win32compat/ssh-agent/connection.c#L51-L111) closes the connection and terminates the process if `process_request` returns a non-zero value.

```C
			if (process_request(con) != 0) {
				ABORT_CONNECTION_RETURN(con);
			}
```

## Why Issues Do Not Arise with Windows ssh-agent and SSH Clients

SSH clients open a new communication channel for each request to `ssh-agent`. This ensures that even if the connection is lost due to a failed `session-bind@openssh.com` request, subsequent requests will reconnect, preventing issues from surfacing.

- Windows uses NamedPipe.
- *nix uses Unix Domain Socket.

For example, the `ssh-add -l` equivalent request involves opening a new connection each time. This behavior ensures resilience against connection failures.

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

Therefore, even if `session-bind@openssh.com` fails and the connection to `ssh-agent` is lost due to some issue, the next agent request will reconnect, preventing the problem from surfacing.
