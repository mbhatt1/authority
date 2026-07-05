int tls_set_cacert(void *cert, u64 len);
int tls_connect(ip_addr_t *addr, u16 port, sstring hostname, connection_handler ch);
