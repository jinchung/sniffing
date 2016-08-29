do
    local segs = {}
    local rqconvs = {}
	local problems = {}
	local log_file = io.open("./p8_xml.log","w")
    local h_resp = Field.new("http.response")
    local h_req = Field.new("http.request")
    local f_eth_type = Field.new("vlan.etype")
    local f_ip_shost = Field.new("ip.src_host")
    local f_ip_dhost = Field.new("ip.dst_host")
    local f_tcp_sport = Field.new("tcp.srcport")
    local f_tcp_dport = Field.new("tcp.dstport")
    local f_tcp_seq   = Field.new("tcp.seq")
    local f_tcp_ack   = Field.new("tcp.ack")
    local f_tcp_stream = Field.new("tcp.stream")
    local f_ip_len     = Field.new("ip.hdr_len")
    local f_tcp_len    = Field.new("tcp.hdr_len")
	local f_tcp_plen   = Field.new("tcp.len")
    local f_vlan_trailer = Field.new("vlan.trailer")
    local f_tcp_flags    = Field.new("tcp.flags")

    local function createDir (dirname)
        os.execute("mkdir " .. dirname)
    end

    local trace_dir = "p8_reports"
    createDir(trace_dir)

    function get_payload(tvb)
        local tcplen =  f_tcp_len().value
        local iplen  =  f_ip_len().value
        local eframe_len
        if f_eth_type() ~= nil and f_eth_type().value == 0x8100 then eframe_len = 14 else eframe_len = 18 end
        local vlan_tlen = 0
        vlan_tlen = 0
        if f_vlan_trailer()
        then
            vlan_tlen=tostring(f_vlan_trailer().value):len()/2
        end
        if eframe_len + tcplen + iplen + vlan_tlen >= tvb:len()
        then
            return nil
        end
        local dataoffset = eframe_len + tcplen + iplen
        local tvb_len = tvb:len() - vlan_tlen - dataoffset
        local xmldata_tvb   = tvb(dataoffset,tvb_len)
        local xmldata = xmldata_tvb:string()
        return xmldata
    end

    local tcp_tap = Listener.new("tcp")

    function tcp_tap.packet(pinfo,tvb,tcp)
        local sno = f_tcp_stream().value
        local shost = f_ip_shost().value
        local dhost = f_ip_dhost().value
		local is_error = 0
		if not segs[sno]
		then
			segs[sno] = {}
			segs[sno][shost]={}
			segs[sno][shost]["nextseq"] = 1
			segs[sno][dhost] = {}
			segs[sno][dhost]["nextseq"] = 1
			problems[sno] = {["file"] = nil,["problems"] = {}}
			if bit.band(f_tcp_flags().value,0x002) ~= 0x002
			then
				table.insert(problems[sno]["problems"],"Stream " .. sno .. " started without SYN")
				log_file:write(sno .. "," .. pinfo.number .. "," .. " started without SYN\n")
			end
		end
		if segs[sno][dhost]["lastack"] ~= nil
		then
			if segs[sno][dhost]["lastack"] > f_tcp_seq().value
			then

				table.insert(problems[sno]["problems"],"Apparently duplicate segment"..
					" lastack = " .. segs[sno][dhost]["lastack"].."seq = "..f_tcp_seq().value)
				is_error = 1
			end
		end

		segs[sno][shost]["nextseq"] = segs[sno][shost]["nextseq"] + f_tcp_seq().value + f_tcp_plen().value
		local rindex = f_tcp_stream().value .. ":" .. f_ip_shost().value
		-- check if ack
		if bit.band(f_tcp_flags().value,0x010) == 0x010
		then
			if segs[sno][dhost]["nextseq"]	~= 0
			then
				if segs[sno][dhost]["nextseq"] < f_tcp_ack().value
				then
					log_file:write(sno .. "," .. pinfo.number .. "," .. "Possiby lost segment \n")
					table.insert(problems[sno]["problems"],"Looks like we lost a segment (ack > next seq) "..
						"next sequence = ".. segs[sno][dhost]["nextseq"].." ack = "..f_tcp_ack().value)
					is_error = 1
				end
			else
				log_file:write(sno .. "," .. pinfo.number .. "," .. "Ack of unseen segment: stream\n")
				table.insert(problems[sno]["problems"],"Ack of unseen segment at " .. 
					sno .. pinfo.number .. f_tcp_ack().value)
				is_error = 1
			end
			segs[sno][shost]["lastack"] = f_tcp_ack().value
		end

		--- fin processing
		if bit.band(f_tcp_flags().value,0x001) == 0x001
		then
			print("=======================> fin","\n")
			if rqconvs[rindex] ~= nil and rqconvs[rindex][2] ~= nil and rqconvs[rindex][2] ~= ""
			then
				print("Data left:",rindex)
				log_file:write(f_tcp_stream().value .. "," .. pinfo.number .. "," .. "Saw a fin with data left " .. rindex .. "\n")
				table.insert(problems[sno]["problems"],"FIN flag with data left over:\n" ..
					rqconvs[rindex][2])
				is_error = 1
			end

			local rrindex = f_tcp_stream().value .. ":" .. f_ip_dhost().value
			if rqconvs[rrindex] ~= nil and rqconvs[rrindex][2] ~= nil and rqconvs[rrindex][2] ~= ""
			then
				print("RData left",rrindex)
				log_file:write(f_tcp_stream().value .. "," .. pinfo.number .. "," .. "Saw a fin with data left " .. rrindex .. "\n")
				table.insert(problems[sno]["problems"],"FIN flag with rdata left over:\n" ..
					rqconvs[rrindex][2])
				is_error = 1
			end

		end
		--- end fin processing
		local pl = get_payload(tvb)
		if pl
		then
			local rdata = rqconvs[rindex]
			if not rdata
			then
				rqconvs[rindex] = {pinfo.abs_ts,"",["segs"] = {}}
			end
			rqconvs[rindex][2] = rqconvs[rindex][2] .. pl
			table.insert(rqconvs[rindex]["segs"],pinfo.number)
		end
		if is_error == 1
		then
			if problems[sno]["file"] == nil

			then
				problems[sno]["file"]  = io.open(trace_dir .. "/" .. "00stream_" .. sno .. "_problems.txt","a")
			end

			problems[sno]["file"]:write(pinfo.number,",")
			for i,v in ipairs(problems[sno]["problems"])
			do
				problems[sno]["file"]:write(v,",")
			end
			problems[sno]["file"]:write("\n")
			problems[sno]["file"]:close()
			problems[sno]["file"] = nil
			problems[sno]["problems"] = {}
		end
	end
	local tap = Listener.new("http")

	function tap.packet(pinfo,tvb,tcp)

		local ip_src, ip_dst = tostring(pinfo.src), tostring(pinfo.dst)
		local src_prt = tostring(pinfo.src_port)
		local src_dmp, dst_dmp
		if h_req() ~= nil and h_req().value
		then
			log_file:write(f_tcp_stream().value .. "," ..  pinfo.number .. ",recognized as http request \n" )
			local rindex = f_tcp_stream().value .. ":" .. f_ip_shost().value
			local rdata = rqconvs[rindex] 
			if not rdata
			then
				rqconvs[rindex] =  {pinfo.abs_ts,get_payload(tvb),["segs"]={}}
			end
			log_file:write(f_tcp_stream().value .. "," .. pinfo.number .. "," .. "Output triggered for segments ")
			for i,v in ipairs(rqconvs[rindex]["segs"])
			do
				log_file:write(v,",")
			end
			log_file:write("\n")

			local wtr = io.open(trace_dir .. "/"  .."capture_" .. 
				f_ip_dhost().value .. "." .. f_tcp_stream().value..".out","a")
			local ts = rqconvs[rindex][1]
			wtr:write("Request arrival timing: (" .. pinfo.number .. ")" .. 
				os.date("%Y-%m-%d %H:%M:%S",pinfo.abs_ts) .. 
				"." .. string.format("%04d",10000 * (pinfo.abs_ts - math.floor(pinfo.abs_ts))).."\n")
			wtr:write("Request data:\n")
			wtr:write(rqconvs[rindex][2])
			wtr:write("\n")
			wtr:flush()
			wtr:close()
			rqconvs[rindex] = nil
		else
			print("============Not a request>",pinfo.number,"\n")
		end

		if h_resp()
		then
			print("========tap response>",pinfo.number,"\n")
			log_file:write(f_tcp_stream().value .. 
				"," .. 
				pinfo.number ..
				",Truncating response " .. 
				f_tcp_stream().value .. 
				" " .. pinfo.number .. "\n")
		    local rindex = f_tcp_stream().value .. ":" .. f_ip_shost().value
			rqconvs[rindex] = nil

		end
	end

	function tap.draw()
	end

	function tap.reset()
		rqconvs = {}
	end

	function tcp_tap.draw()
	end

	function tcp_tap.reset()
	end
end
