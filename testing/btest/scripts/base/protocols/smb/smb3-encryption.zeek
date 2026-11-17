# @TEST-DOC: Verify SMB3 encryption capabilities, session flags, and transform headers are exposed and marked in SMB state and logs.
#
# @TEST-EXEC: zeek -b -r $TRACES/smb/smb3.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m uid path share_type encrypted smb_mapping.log
# @TEST-EXEC: zeek -b -r $TRACES/smb/smb311.pcap %INPUT >out311
# @TEST-EXEC: btest-diff out311
# @TEST-EXEC: test ! -f analyzer.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/smb

global first_transform = T;
global transform_count = 0;

event smb2_negotiate_response(c: connection, hdr: SMB2::Header, response: SMB2::NegotiateResponse)
	{
	print fmt("negotiate dialect=%s capabilities=%s", SMB2::dialects[response$dialect_revision], response$capabilities);
	}

event smb2_session_setup_response(c: connection, hdr: SMB2::Header, response: SMB2::SessionSetupResponse)
	{
	print fmt("session_setup session_id=%s flags=%s", hdr$session_id, response$flags);
	}

event smb2_transform_header(c: connection, hdr: SMB2::Transform_header)
	{
	++transform_count;

	if ( first_transform )
		{
		first_transform = F;
		print fmt("first_transform encrypted=%s compressed=%s session_id=%s state_encrypted=%s",
		          hdr$encrypted, hdr$compressed, hdr$session_id, c$smb_state$encrypted);
		}
	}

event connection_state_remove(c: connection)
	{
	if ( ! c?$smb_state )
		return;

	print fmt("connection_state encrypted=%s negotiated=%s session_id=%s transforms=%d",
	          c$smb_state$encrypted, c$smb_state$encryption_negotiated,
	          c$smb_state?$encrypted_session_id ? c$smb_state$encrypted_session_id : 0,
	          transform_count);
	}
