
# @realSlacker007
# @killswitch-gui
@load base/utils/files.bro

module Conn;

# store the time the prev connection was established
global last_connection_time: time;


# boolean value to indicate whether we have seen a prev connection
global connection_seen: bool = F;

event connection_established(c: connection)

	{
	local net_time: time = network_time();
#	print fmt("%s: New connection established from:::::::::::::::: %s to %s", strftime("%Y/%M/%d %H:%m:%S", net_time), c$id$orig_h, c$id$resp_h);
	if ( connection_seen )
#	print fmt(" Time since last connection: %s", net_time - last_connection_time);

	last_connection_time = net_time;
	connection_seen = T;
	}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count){
	local net_time: time = network_time();	

		if (c$dns?$query)
		{
#		print fmt("NEW DNS:::: LEN %s UID %s REQUESTOR %s RESPONSE %s REQUESTED URL: %s ", len, c$dns$uid, c$id$orig_h, c$id$resp_h, c$dns$query);
		}
		else
#		print fmt("NEW DNS:::: LEN %s UID %s REQUESTOR %s RESPONSE %s ", len, c$dns$uid, c$id$orig_h, c$id$resp_h);

	
	last_connection_time = net_time;
	connection_seen = T;
	}






