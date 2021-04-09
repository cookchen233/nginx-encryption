local cjson = require "cjson"
local common_path = '/usr/local/nginx/conf/lua/enc_request_data/?.lua;'
package.path = common_path .. package.path
local dist_fields = require "dist_fields"
local rsa = require "rsa"
local util = require "util"

local function enc_arr(data)
    local is_enc, is_e = false, false
    if type(data) == "table" then
        for k,v in pairs(data) do
            if util.in_array(k, dist_fields) or util.in_array(string.gsub(k, "%[]", ""), dist_fields) then
            -- if util.in_array(k, dist_fields) then
                if type(v) ~= "table" then
                    is_enc = true
                    data[k] = rsa.encrypt(v)
                    ngx.ctx.enc_data={k, v, data[k]}
                else
                    for k1, v1 in pairs(v) do
                        if type(v1) == "table" then
                            data[k][k1], is_e = enc_arr(v1)
                        else
                            is_enc = true
                            data[k][k1] = rsa.encrypt(v1)
                            ngx.ctx.enc_data={k1, v1, data[k][k1]}
                        end
                    end
                end
            else
                data[k],is_e = enc_arr(v)
            end
        end
    end
    return data, is_enc
end

local function get_form_args()
    -- 返回args 和 文件md5
    local args = {}
    local file_args = {}
    local is_multipart = false
    local headers = ngx.req.get_headers()
    local error_code = 0
    local error_msg = "未初始化"
    local file_md5 = ""
  
    if string.sub(headers.content_type,1,20) == "multipart/form-data;" then--判断是否是multipart/form-data类型的表单  
        is_multipart = true
        local body_data = ngx.req.get_body_data()--body_data可是符合http协议的请求体，不是普通的字符串  
        --请求体的size大于nginx配置里的client_body_buffer_size，则会导致请求体被缓冲到磁盘临时文件里，client_body_buffer_size默认是8k或者16k  
        if not body_data then  
            local datafile = ngx.req.get_body_file()
        
            if not datafile then  
                error_code = 1  
                error_msg = "no request body found"  
            else  
                local fh, err = io.open(datafile, "r")  
                if not fh then  
                    error_code = 2  
                    error_msg = "failed to open " .. tostring(datafile) .. "for reading: " .. tostring(err)  
                else  
                    fh:seek("set")  
                    body_data = fh:read("*a") 
                    fh:close()  
                    if body_data == "" then  
                        error_code = 3  
                        error_msg = "request body is empty"  
                    end  
                end  
            end  
        end  
        local new_body_data = {}  
        --确保取到请求体的数据  
        if error_code == 0 then
            local boundary = "--" .. string.sub(headers.content_type,31)
            -- 兼容处理：当content-type中取不到boundary时，直接从body首行提取。
            local body_data_table = util.explode(tostring(body_data), boundary)  
            local first_string = table.remove(body_data_table,1)
            local last_string = table.remove(body_data_table)
            -- log(">>>>>>>>>>>>>>>>>>>>>start\n", table.concat(body_data_table,"<<<<<<>>>>>>"), ">>>>>>>>>>>>>>>>>>>>>end\n")
            for i,v in ipairs(body_data_table) do
                local start_pos,end_pos,temp_param_name = string.find(v,'Content%-Disposition: form%-data; name="((.+)"; filename="(.*))"')  
                if start_pos then
                    --文件类型的参数，capture是参数名称，capture2是文件名
                    table.insert(file_args, v)
                    table.insert(new_body_data,v)
                else
                    --普通参数
                    local t = util.explode(v,"\r\n\r\n")
                    --[[
                        按照双换行切分后得到的table
                        第一个元素，t[1]='
                        Content-Disposition: form-data; name="_data_"
                        Content-Type: text/plain; charset=UTF-8
                        Content-Transfer-Encoding: 8bit
                        '
                        第二个元素，t[2]='{"fileName":"redis-use.png","bizCode":"1099","description":"redis使用范例.png","type":"application/octet-stream"}'
            
                        从第一个元素中提取到参数名称，第二个元素就是参数的值。
                    ]]
                    local param_name_start_pos, param_name_end_pos, temp_param_name = string.find(t[1],'Content%-Disposition: form%-data; name="(.+)"')   
                    local temp_param_value = string.sub(t[2],1,-3)
                    table.insert(args, {temp_param_name, temp_param_value}) 
                end
                table.insert(new_body_data,1,first_string)
                table.insert(new_body_data,last_string)
                --去掉app_key,app_secret等几个参数，把业务级别的参数传给内部的API
                body_data = table.concat(new_body_data,boundary)--body_data可是符合http协议的请求体，不是普通的字符串
            end
        end  
    else  
      -- 普通post请求
      args = ngx.req.get_post_args()
      --[[
        请求体的size大于nginx配置里的client_body_buffer_size，则会导致请求体被缓冲到磁盘临时文件里
        此时，get_post_args 无法获取参数时，需要从缓冲区文件中读取http报文。http报文遵循param1=value1&param2=value2的格式。
      ]]
      if not args then
          args = {}
          -- body_data可是符合http协议的请求体，不是普通的字符串
          local body_data = ngx.req.get_body_data()
          -- client_body_buffer_size默认是8k或者16k
          if not body_data then
              local datafile = ngx.req.get_body_file()
              if not datafile then
                  error_code = 10
                  error_msg = "no request body found"
              else
                  local fh, err = io.open(datafile, "r")
                  if not fh then
                      error_code = 20
                      error_msg = "failed to open " .. tostring(datafile) .. "for reading: " .. tostring(err)
                  else
                      fh:seek("set")
                      body_data = fh:read("*a")
                      fh:close()
                      if body_data == "" then
                          error_code = 30
                          error_msg = "request body is empty"
                      end
                  end
              end
          end
          -- 解析body_data
          local post_param_table = util.explode(tostring(body_data), "&")
          for i,v in ipairs(post_param_table) do
              local paramEntity = util.explode(v,"=")
              local tempValue = paramEntity[2]
              -- 对请求参数的value进行unicode解码
              tempValue = unescape(tempValue)
              args[paramEntity[1]] = tempValue
          end
      end
    end 
    return args, file_args, is_multipart, file_md5;
end

local function multipart_args_encode(args, file_args)
    local form_str = ""
    local headers = ngx.req.get_headers()
    local boundary = "--" .. string.sub(headers.content_type, 31)
    for k, v in pairs(file_args) do
        form_str = form_str .. boundary..v
    end
    for k, v in pairs(args) do
        form_str = form_str .. boundary..'\r\nContent-Disposition: form-data; name="'..v[1]..'"\r\n\r\n'..v[2]..'\r\n'
    end
    return form_str .. boundary..'\r\n'
end

xpcall(function ()
    local is_enc = false
    local args = ngx.req.get_uri_args()
    args, is_enc = enc_arr(args)
    if is_enc then
        ngx.req.set_uri_args(args)
    end
    if(ngx.req.get_method() == 'POST') then
        util.log("post")
        local is_enc = false
        ngx.req.read_body()
        local headers = ngx.req.get_headers()
        util.log(headers.content_type)
        if string.find(string.lower(headers.content_type), "application/json") then
            util.log("解析 json")
            args = cjson.decode(ngx.req.get_body_data())
            args, is_enc = enc_arr(args)
            body = cjson.encode(args)
        else
            util.log("解析表单")
            args, file_args, is_multipart = get_form_args()
            if args then
                if is_multipart then
                    util.log("multipart 表单")
                    for k, v in pairs(args) do
                        obj = {}
                        obj[v[1]] = v[2]
                        obj,is_e = enc_arr(obj)
                        args[k] = {v[1], obj[v[1]]}
                        if is_e then
                            is_enc = true
                        end
                    end
                    body = multipart_args_encode(args, file_args)
                else
                    util.log("普通表单")
                    args, is_enc = enc_arr(args)
                    body = ngx.encode_args(args)
                end
            end
        end
        if is_enc then
            ngx.req.set_body_data(body)
        end
    end
end, function (err) 
    util.log(err)
end)