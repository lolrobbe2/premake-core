local debug = require "debug"
local internalFunctions = {}
local Profile = {
	file = "profile.json",
	output = "",
}

function Profile:new(file)
	local obj = {
		file = file or self.file
	}
	self.__index = self
	setmetatable(obj, self)
	return obj
end

function Profile:writeHeader()
	self.output = string.format([[{"metadata": {
        "source": "PremakeProfiler",
        "startTime": "%s",
        "dataOrigin": "TraceEvents"
    },"traceEvents":[]], os.date("%Y-%m-%dT%X"))
end

function Profile:write_footer()
	local file_handle = io.open(self.file, "w")
	if file_handle then
		file_handle:write(self.output:sub(1, -2) .. "]}")
		self.output = ""
		io.close(file_handle)
	end
end

local function jsonEscape(str)
	return str
		:gsub("\\", "\\\\")
		:gsub('"', '\\"')
end
function Profile:writeStart(name, ts)
	local json = [[
    {
        "args":{},
        "cat": "function",
        "ph": "B",
        "name": "%s",
        "pid": 0,
        "tid": 0,
        "ts": %f
    },]]

	self.output = self.output .. string.format(json, jsonEscape(name), ts)
end

function Profile:writeEnd(name, ts)
	local json = [[
    {
        "args":{},
        "cat": "function",
        "ph": "E",
        "name": "%s",
        "pid": 0,
        "tid": 0,
        "ts": %f
    },]]

	self.output = self.output .. string.format(json, jsonEscape(name), ts)
end

instrumentator = {
	-- Clock milliseconds to nanoseconds
	clock = function() return os.clock() * 1000000 end,
	profile = nil,
	tailCalls = 0,
	functionStack = {},
	scopeStack = {},
}

function instrumentator:createHook()
	return function(event, _line, info)
		info = info or debug.getinfo(2)
		local func = info.func

		-- Ignore internal or C functions in trace
		if internalFunctions[func] or info.what ~= "Lua" then
			return
		end

		local _, stack_depth = debug.traceback():gsub("\n", "\n")
		if info.istailcall == true then
			stack_depth = stack_depth - 1
		end

		if event == "tail call" then

			if not instrumentator.functionStack[func] then
				instrumentator.functionStack[func] = {}
			end

			instrumentator.functionStack[func][stack_depth] = instrumentator.clock()
			instrumentator.profile:writeStart(info.name or info.short_src, instrumentator.functionStack[func][stack_depth])
		end

		if event == "call" then
			if not instrumentator.functionStack[func] then
				instrumentator.functionStack[func] = {}
			end

			instrumentator.functionStack[func][stack_depth] = instrumentator.clock()
			local name = info.name or info.short_src
    		instrumentator.profile:writeStart(name, instrumentator.functionStack[func][stack_depth])
		end

		if event == "return" then
			if not instrumentator.functionStack[func] then
				return
			end

			local function _write(id, depth)
				if instrumentator.functionStack[func][depth] == nil then
					-- TODO: There is probably an issue with calculating the tail calls
					-- depth here. Need to investigate further.
					return
				end

				local name = info.name or info.short_src
				local start_time = instrumentator.functionStack[func][depth]
				local end_time = instrumentator.clock() - start_time

				-- Avoid 0 values for end_time as it can get interpreted as "forever"
				if end_time < 1 then end_time = 1 end

				instrumentator.profile:writeEnd(name, start_time, end_time)
				instrumentator.functionStack[func][depth] = nil
			end

			if info.istailcall == true then
				for i = instrumentator.tailCalls, 1, -1 do
					_write(info.name or info.short_src, stack_depth + i)
				end
				instrumentator.tailCalls = 0
			end

			_write(info.name or info.short_src, stack_depth)

			-- Clean-up
			if next(instrumentator.functionStack[func]) == nil then
				instrumentator.functionStack[func] = nil
			end
		end
	end
end

function instrumentator:beginSession(file)
	if instrumentator.profile then
		error(string.format(
			"Instrumentor:beginSession('%s'), but another session '%s' is already open.",
			file or "", instrumentator.profile.file), 2)
	end

	instrumentator.profile = Profile:new(file)
	instrumentator.profile:writeHeader()

	debug.sethook(instrumentator:createHook(), "cr")
end

function instrumentator:scope(name)
	local info = debug.getinfo(1)
	local scope_name = string.format("%s(%s:%s)", name, info.short_src, info.linedefined)
	instrumentator.scopeStack[name] = instrumentator.clock()
	instrumentator.profile:writeStart(scope_name, instrumentator.clock())

	local function __close()
		if not instrumentator.scopeStack[name] then
			return
		end

		local info = debug.getinfo(2)
		local scope_name = string.format("%s(%s:%s)", name, info.short_src, info.linedefined)
		local start_time = instrumentator.scopeStack[name]
		local end_time = instrumentator.clock() - start_time

		-- Avoid 0 values for end_time as it can get interpreted as "forever"
		if end_time < 1 then end_time = 1 end

		instrumentator.profile:writeEnd(scope_name, instrumentator.clock())
		instrumentator.scopeStack[name] = nil
	end

	local closable = { close = __close }
	setmetatable(closable, { __close = __close })
	internalFunctions[__close] = true

	return closable
end

function instrumentator:endSession()
	debug.sethook()
	instrumentator.profile:write_footer()
	instrumentator.profile = nil;
end

local function collectFunction(from, into)
	for _, v in pairs(from) do
		if type(v) == "function" then
			into[v] = true
		end
	end
end

internalFunctions[collectFunction] = true
collectFunction(instrumentator, internalFunctions)
collectFunction(Profile, internalFunctions)

premake.tools.instrumentator = instrumentator
