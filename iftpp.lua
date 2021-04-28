--[[
	Author: Jonathan Alter

]]--

iftpp = Proto("IFTPP",  "Insecure File Transport Protocol over Ping")


proto_identifier = ProtoField.int32("iftpp.iftpp_id", "IFTPP Identifier", base.DEC)
size = ProtoField.uint32("iftpp.payload_size", "Payload size", base.DEC)
payload = ProtoField.bytes("iftpp.payload", "Payload")

-- payload options
cl_key = ProtoField.bytes("iftpp.cl_key", "Client Key") 								-- 2
srv_key = ProtoField.bytes("iftpp.srv_key", "Server Key") 								-- 3
requested_file = ProtoField.string("iftpp.requested_file", "requested_file")			-- 4
file_dat = ProtoField.bytes("iftpp.file_data", "File Data")								-- 5
file_checksum = ProtoField.uint64("iftpp.file_checksum", "File Checksum", base.DEC_HEX)	-- 6

actual_payload_size = ProtoField.uint32("iftpp.real_payload_size", "Real payload size", base.DEC)

session_id = ProtoField.uint32("iftpp.sid", "Session ID", base.DEC)
checksum = ProtoField.uint64("iftpp.checksum", "Checksum",base.DEC_HEX)
flag = ProtoField.int8("iftpp.flag","Flag", base.DEC)

-- Declare all of the fields
iftpp.fields = {proto_identifier, size, actual_payload_size, payload, cl_key, srv_key, requested_file, file_dat, file_checksum, session_id , checksum, flag}

-- Get the ICMP dissector by name, not by value in DissectorTable.get("ip.proto").get_dissector(1)
local icmp_dissector = Dissector.get("icmp")
-- local data_dis = Dissector.get("data")



function iftpp.dissector(buffer, pinfo, tree)
	length = buffer:len()
	total_size = buffer():len()
	base_offset = 8
	proto_id_sz = 3
	checksum_sz = 8
	flag_size = 1
	sid_sz = 2
	flag_tot_size = 2

	if length == 0 then return end  
	-- First, call the ICMP dissector
	icmp_dissector:call(buffer():tvb(), pinfo, tree)
  
	-- Check the first 3 data bytes, if these are 0xeb0412, it is an IFTPP traffic
	local data_code = buffer(base_offset, proto_id_sz):uint()

	if data_code == 0xeb0412 then -- = 0xeb0412
		-- pinfo.cols.info = "This is a test"

		-- We are now dealing with our special IFTPP traffic
		pinfo.cols.protocol = iftpp.name
		local subtree = tree:add(iftpp, buffer(base_offset):tvb()) --"Insecure File Transport Protocol over Ping")
		-- ALL HAVE THIS PROTO ID FIELD

		subtree:add_le(proto_identifier, buffer(base_offset, proto_id_sz)) -- Protocol Identifier 0xeb0412


		flg_buf = buffer(total_size-1,1) -- read last byte
		flg = flg_buf:uint()
		local flg_code_name = "UNKNOWN"
		-- Set the name for the flag type 
		if 	   flg == 0 then flg_code_name = "SESSION_INIT"
		elseif flg == 1 then flg_code_name = "ACK"
		elseif flg == 2 then flg_code_name = "CL_KEY"
		elseif flg == 3 then flg_code_name = "SRV_KEY"
		elseif flg == 4 then flg_code_name = "FILE_REQ"
		elseif flg == 5 then flg_code_name = "FILE_DAT"
		elseif flg == 6 then flg_code_name = "FIN"
		elseif flg == 7 then flg_code_name = "RETRAN" end
		
		--- DYNAMIC PARSING FROM HERE

		if flg < 1 or flg > 7 then
			flag_tot_size = 0
		end 

		if flg == 5 then
			-- assuming size field is one byte, how big is the payload?
			pyld_size_if_one_byte = total_size - base_offset - 1 - flag_tot_size - checksum_sz - sid_sz - proto_id_sz
			-- Subsequent testing has found this logic flawed.
			if pyld_size_if_one_byte > 256 then
				payload_size_sz = 2
			else
				payload_size_sz = 1
			end
		else

			payload_size_sz = 1
		end

		if flg == 1 then 
			sid_sz = 0
			checksum_sz = 0
		end 

		subtree:add_le(size, buffer(base_offset + proto_id_sz,payload_size_sz))
		---sz = buffer(base_offset + proto_id_sz,payload_size_sz):uint()
		real_size = total_size - base_offset - payload_size_sz - flag_tot_size - checksum_sz - sid_sz - proto_id_sz
		subtree:add(actual_payload_size, real_size)
		-- print(real_size)
		-- extract the payload as a buffer
		local pyld_buffer = buffer(base_offset + proto_id_sz + payload_size_sz, real_size)
		
		-- Depending on the flag code, interpret the payload differently
		if flg == 1 then
			ackval = pyld_buffer:string()
			if ackval == "fDataAck" then
				flg_code_name = flg_code_name .. " / File Data ACK"
			elseif ackval == "finAck" then
				flg_code_name = flg_code_name .. " - FINACK"
			elseif ackval == "sidAck" then
				flg_code_name = flg_code_name .. " - Session ID ACK"
			end
			subtree:add_le(payload, pyld_buffer)
		elseif flg == 2 then
			subtree:add_le(cl_key, pyld_buffer)
		elseif flg == 3 then
			subtree:add_le(srv_key, pyld_buffer)
		elseif flg == 4 then
			subtree:add_le(requested_file, pyld_buffer)
		elseif flg == 5 then
			subtree:add_le(file_dat, pyld_buffer)
		elseif flg == 6 then
			subtree:add_le(file_checksum, pyld_buffer)
		else -- flg == 7 not seen in PCAP 
			subtree:add_le(payload, pyld_buffer)
		end


		if checksum_sz ~= 0 then
			subtree:add_packet_field(checksum, buffer(total_size -(flag_tot_size + checksum_sz), checksum_sz), ENC_BIG_ENDIAN)
		end
		if sid_sz ~= 0 then
			subtree:add_le(session_id, buffer(total_size - (flag_tot_size + checksum_sz + sid_sz), sid_sz))
		end
		if flag_tot_size ~= 0 then
			subtree:add_le(flag, flg_buf):append_text("  ("..flg_code_name..")  ")
		end
		pinfo.cols.info = "["..flg_code_name.."]"
	end
end

-- this proto runs on ICMP so no ports

local ip_proto = DissectorTable.get("ip.proto")
-- Have IFTPP added to protocol number 1 in the IP proto field
ip_proto:add(1,iftpp)
-- uncomment to keep both dissectors and default to icmp
-- ip_proto:add(1,icmp_dissector)