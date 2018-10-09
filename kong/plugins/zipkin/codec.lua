local to_hex = require "resty.string".to_hex
local new_span_context = require "opentracing.span_context".new

local function hex_to_char(c)
	return string.char(tonumber(c, 16))
end

local function from_hex(str)
	if str ~= nil then -- allow nil to pass through
		str = str:gsub("%x%x", hex_to_char)
	end
	return str
end

local function extract_from_b3_http_headers(warn, headers)
	local trace_id = headers["x-b3-traceid"]
	-- Validate trace id
	if trace_id and ((#trace_id ~= 16 and #trace_id ~= 32) or trace_id:match("%X")) then
		warn("x-b3-traceid header invalid; ignoring.")
		return nil
	end

	if trace_id == nil then
		return nil
	end

	local parent_span_id = headers["x-b3-parentspanid"]
	-- Validate parent_span_id
	if parent_span_id and (#parent_span_id ~= 16 or parent_span_id:match("%X")) then
		warn("x-b3-parentspanid header invalid; ignoring.")
		return nil
	end

	local request_span_id = headers["x-b3-spanid"]
	-- Validate request_span_id
	if request_span_id and (#request_span_id ~= 16 or request_span_id:match("%X")) then
		warn("x-b3-spanid header invalid; ignoring.")
		return nil
	end

	-- X-B3-Sampled: if an upstream decided to sample this request, we do too.
	local sample = headers["x-b3-sampled"]
	if sample == "1" or sample == "true" then
		sample = true
	elseif sample == "0" or sample == "false" then
		sample = false
	elseif sample ~= nil then
		warn("x-b3-sampled header invalid; ignoring.")
		sample = nil
	end

	-- X-B3-Flags: if it equals '1' then it overrides sampling policy
	-- We still want to warn on invalid sample header, so do this after the above
	local debug = headers["x-b3-flags"]
	if debug == "1" then
		sample = true
	elseif debug ~= nil then
		warn("x-b3-flags header invalid; ignoring.")
	end
		
	-- Process jaegar baggage header
	local baggage = {}
	for k, v in pairs(headers) do
		local baggage_key = k:match("^uberctx%-(.*)$")
		if baggage_key then
			baggage[baggage_key] = ngx.unescape_uri(v)
		end
	end

	trace_id = from_hex(trace_id)
	parent_span_id = from_hex(parent_span_id)
	request_span_id = from_hex(request_span_id)

	-- Consider to set flags to span_context.
	return new_span_context(trace_id, request_span_id, parent_span_id, sample, baggage)
end

local function extract_from_trace_context_header(warn, headers, header_name)
	-- Jaeger Trace/Span identity
	-- see: https://jaeger.readthedocs.io/en/stable/client_libraries/#tracespan-identity
	local context_value = headers[header_name]
	if context_value == nil or context_value == "" then
		return nil
	end
	context_value = ngx.unescape_uri(context_value)

	local parts = {}
   	context_value:gsub("([^:]+)", function(c) parts[#parts+1] = c end)
	if #parts ~= 4 then
		return nil
	end

	local trace_id = parts[1]
	-- Validate trace id
	if trace_id and ((#trace_id ~= 16 and #trace_id ~= 32) or trace_id:match("%X")) then
		warn(header_name.." header, traceid invalid; ignoring.")
		return nil
	end

	if trace_id == nil then
		return nil
	end

	local request_span_id = parts[2]
	-- Validate request_span_id
	if request_span_id and (#request_span_id ~= 16 or request_span_id:match("%X")) then
		warn(header_name.." header, spanid invalid; ignoring.")
		return nil
	end

	local parent_span_id = parts[3]
	-- Validate parent_span_id
	if parent_span_id and (#parent_span_id ~= 16 or parent_span_id:match("%X")) then
		warn(header_name.." header, parent span id invalid; ignoring.")
		return nil
	end

	local flags = tonumber(parts[4])
	-- Validate flags
	local sample = false
	if flags == nil then
		warn(header_name.." header, flags invalid; ignoring.")
		return nil
	elseif flags < 0 or flags > 3 then
		warn(header_name.." header, flags invalid; ignoring.")
		return nil
	elseif flags > 1 then
		-- Debug flag should be turned on here 
		sample = true
	elseif flags == 1 then
		sample = true
	end

	-- Process jaegar baggage header
	local baggage = {}
	for k, v in pairs(headers) do
		local baggage_key = k:match("^uberctx%-(.*)$")
		if baggage_key then
			baggage[baggage_key] = ngx.unescape_uri(v)
		end
	end

	trace_id = from_hex(trace_id)
	request_span_id = from_hex(request_span_id)
	parent_span_id = from_hex(parent_span_id)

	-- Consider to set flags to span_context.
	return new_span_context(trace_id, request_span_id, parent_span_id, sample, baggage)
end

local function new_extractor(warn)
	return function(headers)
		local span_context = extract_from_b3_http_headers(warn, headers)
		if span_context ~= nil then
			return span_context
		end

		return extract_from_trace_context_header(warn, headers, "uber-trace-id")
	end
end

local function inject_b3_http_headers(span_context, headers)
	-- We want to remove headers if already present
	headers["x-b3-traceid"] = to_hex(span_context.trace_id)
	headers["x-b3-parentspanid"] = span_context.parent_id and to_hex(span_context.parent_id) or nil
	headers["x-b3-spanid"] = to_hex(span_context.span_id)
	-- Get flags from request headers
	-- Consider to get flags from span_context.
	local Flags = ngx.req.get_headers()["x-b3-flags"]
	headers["x-b3-flags"] = Flags
	headers["x-b3-sampled"] = (not Flags) and (span_context.should_sample and "1" or "0") or nil
	for key, value in span_context:each_baggage_item() do
		-- XXX: https://github.com/opentracing/specification/issues/117
		headers["uberctx-"..key] = ngx.escape_uri(value)
	end
end

local function inject_trace_context_http_header(span_context, headers, header_name)
	-- Get flags from request headers
	-- Consider to get flags from span_context.
	local context_value = ngx.req.get_headers()[header_name] 
	flags = "0"
	if context_value ~= nil and context_value ~= "" then
		local parts = {}
		context_value:gsub("([^:]+)", function(c) parts[#parts+1] = c end)
		if #parts == 4 then
			flags = parts[4]
		end
	else 
		-- Get debug flag from x-b3-flags
		local debug = headers["x-b3-flags"]
		if debug == "1" then
			flags = "2"
		elseif span_context.should_sample then
			flags = "1"
		end
	end

	-- Jaeger Trace/Span identity
	-- see: https://jaeger.readthedocs.io/en/stable/client_libraries/#tracespan-identity
	context_value = string.format(
		"%s:%s:%s:%s",
		to_hex(span_context.trace_id),
		to_hex(span_context.span_id),
		to_hex(span_context.parent_id),
		flags
	)

	headers[header_name] = ngx.escape_uri(context_value)
end

local function new_injector()
	return function(span_context, headers)
		set_b3_http_headers(span_context, headers)
		set_trace_context_http_header(span_context, headers, "uber-trace-id")
	end
end

return {
	new_extractor = new_extractor;
	new_injector = new_injector;
}
