import * as readlineSync from 'readline-sync'
import * as requests from 'request'
import * as fs from 'fs'
import { Store } from 'tough-cookie';
import RSA from 'node-rsa'
import * as iconv from 'iconv-lite'
import * as path from 'path'

var FileCookieStore = require('tough-cookie-filestore');

let BAIDUPAN_SERVER = 'pan.baidu.com'
let BAIDUPCS_SERVER = 'pcs.baidu.com'
let BAIDUPAN_HEADERS = {
    "Referer": "http://pan.baidu.com/disk/home",
    "User-Agent": "netdisk;4.6.2.0;PC;PC-Windows;10.0.10240;WindowsBaiduYunGuanJia"
}

class LoginFailed extends Error { }

function check_login() {
    return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
        let func: Function = descriptor.value
        descriptor.value = function () {
            let _ret = func.apply(this, arguments)
            if (_ret && _ret.body && this instanceof PCSBase) {
                let that = this as PCSBase
                try {
                    let ret = _ret as requests.Response
                    let foo = JSON.parse(ret.body)
                    if ("errno" in foo && foo.errno == -6) {
                        let path = `.${that.username}.cookies`
                        if (fs.existsSync(path))
                            fs.unlinkSync(path)
                        that._initiate()
                    }
                } catch (error) {
                    throw new LoginFailed("User unsigned in.")
                }
            }
            return _ret
        }
    };
}

function default_captcha_handler(image_url: string, encoding: string = "gbk"): string {
    console.log("verify code url:")
    console.log(image_url)
    return iconv.decode(new Buffer(readlineSync.question("Input verify code > ", { encoding: 'binary' }), "binary"), encoding)
}
class PCSBase {
    codeString: string | null = null
    // api_template = `http://${BAIDUPAN_SERVER}/api/{0}`
    cookies: requests.CookieJar
    store: Store
    username: string
    password: string
    init: Promise<void>
    user: any = {
    }
    captcha_func: (image_url: string) => string
    verify_func: (msg: string) => string

    constructor(username: string, password: string, captcha_func: (image_url: string) => string = default_captcha_handler, verify_func: (msg: string) => string = readlineSync.question) {
        this.username = username
        this.password = password
        this.captcha_func = captcha_func
        this.verify_func = verify_func
        let cookies_file = `.${this.username}.cookies`
        if (!fs.existsSync(cookies_file)) {
            fs.closeSync(fs.openSync(cookies_file, 'w'));
        }
        this.store = new FileCookieStore(cookies_file)
        this.cookies = requests.jar(this.store)
        PCSBase.set_pcs_server(PCSBase.get_fastest_pcs_server())
        this.init = this._initiate()
    }

    static async get_fastest_pcs_server() {
        let url = 'http://pcs.baidu.com/rest/2.0/pcs/file?app_id=250528&method=locateupload'
        let ret = await new Promise((resolve, reject) => {
            requests.get(url, (err, res, body) => {
                if (!err && res.statusCode == 200) {
                    resolve(body)
                } else {
                    reject(err)
                }
            })
        }) as string
        return JSON.parse(ret)['host']
    }

    static set_pcs_server(server: Promise<string>) {
        server.then(s => BAIDUPCS_SERVER = s).catch(e => { throw e })
    }

    async _initiate() {
        this.user.token = await this._get_token()
        let bduss = await this._find_cookie("baidu.com", "/", "BDUSS")
        if (bduss) {
            this.user.BDUSS = bduss.value
            return;
        }
        await this._login()
    }

    async _login() {
        let captcha = ''
        let code_string = ''
        let [pubkey, rsakey] = await this._get_publickey()
        let rsa = new RSA(pubkey)
        rsa.setOptions({
            encryptionScheme: "pkcs1"
        })
        let password_rsaed = rsa.encrypt(this.password, 'base64')
        let result
        while (true) {
            let login_data = {
                'staticpage': 'http://www.baidu.com/cache/user/html/v3Jump.html',
                'charset': 'UTF-8',
                'token': this.user['token'],
                'tpl': 'pp',
                'subpro': '',
                'apiver': 'v3',
                'tt': parseInt((new Date().getTime() / 1000).toString()).toString(),
                'codestring': code_string,
                'isPhone': 'false',
                'safeflg': '0',
                'u': 'https://passport.baidu.com/',
                'quick_user': '0',
                'logLoginType': 'pc_loginBasic',
                'loginmerge': 'true',
                'logintype': 'basicLogin',
                'username': this.username,
                'password': password_rsaed,
                'verifycode': captcha,
                'mem_pass': 'on',
                'rsakey': (rsakey),
                'crypttype': 12,
                'ppui_logintime': '50918',
                'callback': 'parent.bd__pcbs__oa36qm'
            }
            result = await this._post('https://passport.baidu.com/v2/api/?login', login_data)
            let body: string = result.body
            if (body.includes("err_no=257") || body.includes("err_no=6")) {
                let re = /codeString=(.*?)&/g
                let code_strings = body.match(re)
                if (code_strings) {
                    code_string = code_strings[0].replace("codeString=", "").replace("&", "")
                }
                this.codeString = code_string
                captcha = this._get_captcha(code_string)
                continue
            }
            break
        }
        await this._check_account_exception(result.body)
        if (result.statusCode != 200) {
            throw new LoginFailed("Login failed.");
        }
        this.user.token = await this._get_token()
        await this.user_info()
    }

    async _get_publickey(): Promise<string[]> {
        let url = 'https://passport.baidu.com/v2/getpublickey?token=' + this.user['token']
        let content = (await this._get(url)).body
        let jdata = JSON.parse(content.replace(/'/g, '"'))
        return [jdata.pubkey, jdata.key]
    }

    _post(url: string, data: { [key: string]: any }) {
        return new Promise<requests.Response>((resolve, rejects) => {
            requests.post({
                url: url,
                jar: this.cookies,
                form: data,
                callback: (error: any, res) => {
                    if (error) {
                        rejects(error)
                    } else {
                        resolve(res)
                    }
                }
            })
        })
    }

    _get(url: string, data: any = {}): Promise<requests.Response> {
        return new Promise<requests.Response>((resolve, reject) => {
            requests.get({
                uri: url,
                jar: this.cookies,
                form: data,
                callback: (error: any, res) => {
                    if (error) {
                        reject(error)
                    } else {
                        resolve(res)
                    }
                }
            })
        })
    }

    async _get_token() {
        let url = `https://passport.baidu.com/v2/api/?getapi&tpl=mn&apiver=v3&class=login&tt=${parseInt((new Date().getTime() / 1000).toString())}&logintype=dialogLogin&callback=0`
        let ret = await this._get("http://www.baidu.com").then(() => this._get(url))
        let foo = JSON.parse(ret.body.replace(/'/g, '"'))
        return foo.data.token
    }

    _get_captcha(code_string: string) {
        if (code_string) {
            return this.captcha_func("https://passport.baidu.com/cgi-bin/genimage?" + code_string)
        } else {
            return ""
        }
    }


    async _check_account_exception(content: string) {
        let err_id = (/err_no=([\d]+)/g.exec(content) as string[])[1]
        if (err_id == '0')
            return
        if (err_id == '120021') {
            let auth_token = (/authtoken=([^&]+)/g.exec(content) as string[])[1]
            let loginproxy_url = (/loginproxy=([^&]+)/g.exec(content) as string[])[1]
            let resp = await this._get('https://passport.baidu.com/v2/sapi/authwidgetverify', {
                'authtoken': auth_token,
                'type': 'email',
                'apiver': 'v3',
                'action': 'send',
                'vcode': '',
                'questionAndAnswer': '',
                'needsid': '',
                'rsakey': '',
                'countrycode': '',
                'subpro': '',
                'callback': '',
                'tpl': 'mn',
                'u': 'https://www.baidu.com/'
            })
            if (resp.statusCode == 200) {
                while (true) {
                    let vcode = this.verify_func("Verification Code")
                    let vresp = await this._get('https://passport.baidu.com/v2/sapi/authwidgetverify', {
                        'authtoken': auth_token,
                        'type': 'email',
                        'apiver': 'v3',
                        'action': 'check',
                        'vcode': vcode,
                        'questionAndAnswer': '',
                        'needsid': '',
                        'rsakey': '',
                        'countrycode': '',
                        'subpro': '',
                        'callback': ''
                    })
                    let vresp_data = JSON.parse(vresp.body)
                    if (vresp_data['errno'] == 110000) {
                        await this._get(loginproxy_url)
                        return
                    }
                }
            } else {
                throw new LoginFailed("发送安全验证请求失败")
            }
        }
        let msg = `unknown err_id=${err_id}`
        if (login_err[err_id]) {
            msg = login_err[err_id].msg
        }
        throw new LoginFailed(msg)
    }

    __request(uri: string, callback: (err: any, resp: requests.Response) => void = () => { }, method: string = "", url: string | any = null, extra_params: any = null, data: any = null, files: NodeJS.ReadableStream | null = null, other: any = {}): requests.Request {
        let params: any = {
            method: method,
            app_id: "250528",
            BDUSS: this.user.BDUSS,
            t: parseInt((new Date().getTime() / 1000).toString()).toString(),
            bdstoken: this.user.token
        }
        if (extra_params)
            for (let key in extra_params)
                params[key] = extra_params[key]
        let headers: any = { ...BAIDUPAN_HEADERS }
        if (other.headers) {
            for (let key in other.headers)
                headers[key] = other.headers[key]
        }
        if (!url) {
            url = `http://${BAIDUPAN_SERVER}/api/${uri}`
        }
        let api = url as string
        for (let key in params) {
            if (api.includes("?")) {
                api = `${api}&${key}=${params[key]}`
            } else {
                api = `${api}?${key}=${params[key]}`
            }
        }
        url = api
        if (data || files) {
            if (data) {
                return requests.post({
                    url: url,
                    form: data,
                    headers: headers,
                    jar: this.cookies,
                    callback: callback
                })
            } else {
                return requests.post({
                    url: url,
                    // form: data,
                    headers: headers,
                    jar: this.cookies,
                    callback: callback,
                    formData: {
                        file: files
                    }
                });
            }
        } else {
            let method: Function
            if (uri == 'filemanager' || uri == 'rapidupload' || uri == 'filemetas' || uri == 'precreate') {
                method = requests.post
            } else {
                method = requests.get
            }
            return method({
                url: url,
                form: params,
                headers: headers,
                jar: this.cookies,
                callback: callback,
                ...other
            })
        }
    }

    @check_login()
    _request(uri: string, method: string = "", url: string | any = null, extra_params: any = null, data: any = null, files: NodeJS.ReadableStream | null = null, other: any = {}) {
        return new Promise<requests.Response>((resolve, reject) => {
            this.__request(uri, (err, resp) => {
                if (err) reject(err)
                else (resolve(resp))
            }, method, url, extra_params, data, files, other)
        })
        // let response: requests.Response
        // let params: any = {
        //     method: method,
        //     app_id: "250528",
        //     BDUSS: this.user.BDUSS,
        //     t: parseInt((new Date().getTime() / 1000).toString()).toString(),
        //     bdstoken: this.user.token
        // }
        // if (extra_params)
        //     for (let key in extra_params)
        //         params[key] = extra_params[key]
        // let headers: any = { ...BAIDUPAN_HEADERS }
        // if (other.headers) {
        //     for (let key in other.headers)
        //         headers[key] = other.headers[key]
        // }
        // if (!url) {
        //     url = `http://${BAIDUPAN_SERVER}/api/${uri}`
        // }
        // let api = url as string
        // for (let key in params) {
        //     if (api.includes("?")) {
        //         api = `${api}&${key}=${params[key]}`
        //     } else {
        //         api = `${api}?${key}=${params[key]}`
        //     }
        // }
        // url = api
        // if (data || files) {
        //     if (data) {
        //         response = await new Promise<requests.Response>((resolve, reject) => {
        //             requests.post({
        //                 url: url,
        //                 form: data,
        //                 headers: headers,
        //                 jar: this.cookies,
        //                 callback: (err, res) => {
        //                     if (err) {
        //                         reject(err)
        //                     } else {
        //                         resolve(res)
        //                     }
        //                 }
        //             })
        //         })
        //     } else {
        //         response = await new Promise<requests.Response>((resolve, reject) => {
        //             fs.createReadStream(files as string).pipe(requests.post({
        //                 url: url,
        //                 form: data,
        //                 headers: headers,
        //                 jar: this.cookies,
        //                 callback: (err, res) => {
        //                     if (err) {
        //                         reject(err)
        //                     } else {
        //                         resolve(res)
        //                     }
        //                 }
        //             }))
        //         })
        //         // requests.post({
        //         //     url: url,
        //         // })
        //     }
        // } else {
        //     let method: Function
        //     if (uri == 'filemanager' || uri == 'rapidupload' || uri == 'filemetas' || uri == 'precreate') {
        //         method = requests.post
        //     } else {
        //         method = requests.get
        //     }
        //     response = await new Promise<requests.Response>((resolve, reject) => {
        //         method({
        //             url: url,
        //             form: params,
        //             headers: headers,
        //             jar: this.cookies,
        //             callback: (err: any, res: requests.Response) => {
        //                 if (err) {
        //                     reject(err)
        //                 } else {
        //                     resolve(res)
        //                 }
        //             },
        //             ...other
        //         })
        //     })
        // }
        // return response
    }

    async user_info() {
        let params = {
            'method': "query",
        }
        let url = 'https://pan.baidu.com/rest/2.0/membership/user'
        return await this._request('membership/user', 'user', url, params, undefined, undefined, arguments)
    }

    _find_cookie(domain: string, path: string, key: string) {
        return new Promise<requests.Cookie | null>((resolve, reject) => {
            this.store.findCookie(domain, path, key, (err, cookie) => {
                if (err) {
                    reject(err)
                } else {
                    resolve(cookie)
                }
            })
        })
    }
}
export default class PCS extends PCSBase {
    /**
     * 获取配额信息  
     * {"errno":0,"total":配额字节数,"used":已使用字节数,"request_id":请求识别号}
     */
    quota() {
        return this._request('quota')
    }

    /**
     * 获取目录下的文件列表 
     * @param remote_path 
     * 网盘中目录的路径，必须以 / 开头,路径长度限制为1000;
     * 径中不能包含以下字符：\ ? | " > < : *;
     * 文件名或路径名开头结尾不能是 . 或空白字符，空白字符包括:
     *  \r, \n, \t, 空格, \0, \x0B;
     * @param by 排序字段，缺省根据文件类型排序
     * @param order 
     * @param limit 返回条目控制
     * @param extra_params 
     * @param is_share 是否是分享的文件夹(大概)
     */
    list_files(remote_path: string, by: "name" | "time" | "size" = "name", order: "desc" | "asc" = "desc", limit: null | { start: number, end: number } = null, extra_params: any = null, is_share = false) {
        let desc = order == "desc" ? "1" : "0"
        let params: any = {}
        if (extra_params) params = { ...extra_params }
        params.dir = remote_path
        params.order = by
        params.desc = desc
        if (is_share) {
            return this._request('/share/list', undefined, "https://pan.baidu.com/share/list", params, undefined, undefined)
        }
        return this._request("list", "list", undefined, params)
    }

    /**
     * 为当前用户创建一个目录
     * @param remote_path 
     * 网盘中目录的路径，必须以 / 开头;
     * 路径长度限制为1000;
     * 径中不能包含以下字符：\ ? | " > < : * ;
     * 文件名或路径名开头结尾不能是 . 或空白字符，空白字符包括:
     * \r, \n, \t, 空格, \0, \x0B 。
     */
    mkdir(remote_path: string) {
        let data = {
            'path': remote_path,
            'isdir': "1",
            "size": "",
            "block_list": "[]"
        }
        return this._request('create', 'post', undefined, undefined, data, undefined, undefined)
    }

    /**
     * 删除文件或文件夹
     * @param path_list  待删除的文件或文件夹列表,每一项为服务器路径
     */
    delete(path_list: string[]) {
        let data = { filelist: JSON.stringify(path_list) }
        let url = `http://${BAIDUPAN_SERVER}/api/filemanager?opera=delete`
        return this._request('filemanager', 'delete', url, undefined, data)
    }

    /**
     * 移动文件或文件夹 
     * @param path_list 在百度盘上要移动的源文件path
     * @param dest 要移动到的目录
     */
    move(path_list: string[], dest: string) {
        let __path = function (path: string) {
            let ps = path.split("/")
            if (path.endsWith("/")) {
                return ps[ps.length - 2]
            } else {
                return ps[ps.length - 1]
            }
        }

        let params = { 'opera': 'move' }
        let filelist = []
        for (let path of path_list) {
            filelist.push({
                path: path,
                dest: dest,
                newname: __path(path)
            })
        }
        let data = {
            filelist: JSON.stringify(filelist),
        }
        let url = `http://${BAIDUPAN_SERVER}/api/filemanager`
        return this._request('filemanager', 'move', url, params, data)
    }

    /**
    * 复制文件或文件夹 
    * @param path_list 在百度盘上要复制的源文件path
    * @param dest 要复制到的目录
    */
    copy(path_list: string[], dest: string) {
        let __path = function (path: string) {
            let ps = path.split("/")
            if (path.endsWith("/")) {
                return ps[ps.length - 2]
            } else {
                return ps[ps.length - 1]
            }
        }

        let params = { 'opera': 'copy' }
        let filelist = []
        for (let path of path_list) {
            filelist.push({
                path: path,
                dest: dest,
                newname: __path(path)
            })
        }
        let data = {
            filelist: JSON.stringify(filelist),
        }
        let url = `http://${BAIDUPAN_SERVER}/api/filemanager`
        return this._request('filemanager', 'copy', url, params, data)
    }

    /**
     * 重命名
     * @param rename_pair_list 需要重命名的文件(夹)(path:路径,newname:新名称)
     */
    rename(rename_pair_list: { path: string, newname: string }[]) {
        let data = { filelist: JSON.stringify(rename_pair_list) }
        let params = { 'opera': 'rename' }
        let url = `http://${BAIDUPAN_SERVER}/api/filemanager`
        return this._request('filemanager', 'rename', url, params, data)
    }

    /**
     * 获得文件(s)的metainfo
     * @param file_list 文件路径列表,如 ['/aaa.txt']
     */
    meta(file_list: string[]) {
        let data = { "target": JSON.stringify(file_list) }
        return this._request("filemetas?blocks=0&dlink=1", "filemetas", undefined, undefined, data)
    }

    /**
     * 获取文件缩略图  
     * 如果返回 HTTP 404 说明该文件不存在缩略图形式  
     * @param path 远程文件路径
     * @param height 缩略图高
     * @param width 缩略图宽
     * @param quality 缩略图质量，默认100
     */
    thumbnail(path: string, height: number, width: number, quality = 100) {
        let params = {
            'ec': 1,
            'path': path,
            'quality': quality,
            'width': width,
            'height': height
        }
        let url = `http://${BAIDUPCS_SERVER}/rest/2.0/pcs/thumbnail`
        return this._request('thumbnail', 'generate', url, params)
    }

    /**
     * 搜索文件
     * @param path 搜索目录
     * @param keyword 关键词
     * @param page 返回第几页的数据
     * @param recursion 
     * @param limit 
     */
    search(path: string, keyword: string, page = 1, recursion = 1, limit = 1000) {
        let params = {
            'dir': path,
            'recursion': recursion,
            'key': keyword,
            'page': page.toString(),
            'num': limit.toString()
        }
        return this._request('search', 'search', undefined, params)
    }

    /**
     * 清空回收站  
     * 大概率会出现错误132(需要手机验证),暂未处理
     */
    clean_recycle_bin() {
        let url = `https://${BAIDUPAN_SERVER}/api/recycle/clear`
        return this._request("recycle", 'clear', url)
    }

    /**
     * 批量还原文件或目录（非强一致接口，调用后请sleep1秒 ）
     * @param fs_ids 所还原的文件或目录在 PCS 的临时唯一标识 ID 的列表
     */
    restore_recycle_bin(fs_ids: string[]) {
        let data = { fidlist: JSON.stringify(fs_ids) }
        return this._request('recycle', 'restore', undefined, undefined, data)
    }

    /**
     * 获取回收站中的文件及目录列表
     * @param by 排序字段，缺省根据时间排序
     * @param order 
     * @param limit 返回条目控制
     * @param page 返回条目的分页控制, 当前页码
     */
    list_recycle_bin(by: "name" | "time" | "size" = "time", order: "desc" | "asc" = "desc", limit: { start: number, end: number } = { start: 0, end: 1000 }, page = 1) {
        let desc = order == "desc" ? "1" : "0"
        let params = {
            'start': limit.start,
            'num': limit.end - limit.start,
            'dir': '/',
            'order': by,
            'desc': desc,
            'page': page
        }
        let url = `https://${BAIDUPAN_SERVER}/api/recycle/list`
        return this._request('recycle', 'list', url, params)
    }

    list_shared_folder(shareid: string, uk: string, path: string, page = 1, number = 100) {
        return this.list_files(path, undefined, undefined, undefined, {
            "shareid": shareid,
            "uk": uk,
            "web": '1',
            "page": page,
            "number": number,
            "showempty": 0,
            "clienttype": 0
        }, true)
    }

    /**
     * 保存分享文件列表到自己的网盘, 支持密码, 支持文件过滤的回调函数
     * @param url 分享的url
     * @param path 保存到自己网盘的位置
     * @param password 分享密码, 如果没有分享资源没有密码则不用填
     * @param filter_callback 过滤文件列表中文件的回调函数, 返回值是假值则被过滤掉
     */
    async save_share_list(url: string, path: string, password: string | null = null, filter_callback: (file: { filename: string, size: number, isdir: number }) => boolean = () => true) {
        let respond = await new Promise<requests.Response>((resolve, reject) => {
            requests.get({
                url: url, callback: (err, resp) => {
                    if (err) reject(err)
                    else resolve(resp)
                }
            })
        })
        let target_url = respond.request.uri.href
        let g = (/surl=([a-zA-Z\d]+)/g.exec(target_url) as string[])
        let surl: string
        if (g) {
            surl = g[1]
        } else {
            surl = (/s\/([a-zA-Z\d]+)/g.exec(target_url) as string[])[1]
        }
        let m_ = /.*yunData\.setData\((.*?)\);.*/g.exec(respond.body)
        if (!m_) {
            if (password) {
                let data = {
                    pwd: password,
                    t: parseInt((new Date().getTime() / 1000).toString()).toString()
                }
                let url2 = `http://pan.baidu.com/share/verify?surl=${surl}`
                respond = await this._request("", undefined, url2, undefined, data)
                let verify_result = JSON.parse(respond.body)
                if (verify_result['errno'] != 0) {
                    return verify_result
                }
            } else {
                return { "errno": -2, "error_msg": "PCS.save_share_list failed, mayby this share need password!" }
            }
        }
        let html = (await this._request("", undefined, url)).body
        let r = /.*yunData\.setData\((.*?)\);.*/g
        let m = r.exec(html)
        if (m) {
            let context = JSON.parse(m[1])
            let file_list: any[] = context.file_list.list
            let uk: string = context.uk.toString()
            let shareid: string = context.shareid.toString()
            let ret: { filelist: string[] } = { filelist: [] }
            for (let f of file_list) {
                let file_obj = {
                    filename: f["server_filename"],
                    size: f["size"],
                    isdir: f["isdir"]
                }
                if (filter_callback(file_obj))
                    ret.filelist.push(f.path)
            }
            let save_share_file_ret = await this._save_shared_file_list(shareid, uk, path, ret.filelist)
            if (save_share_file_ret.errno == 0) {
                return save_share_file_ret
            } else {
                return ret
            }
        } else {
            return { "errno": -1, "error_msg": "PCS.save_share_list failed, mayby url is incorrect!" }
        }
    }

    async _save_shared_file_list(shareid: string, uk: string, path: string, file_list: any) {
        let url = "http://pan.baidu.com/share/transfer?shareid=" + shareid + "&from=" + uk
        let data = {
            "filelist": JSON.stringify(file_list),
            "path": path
        }
        return JSON.parse((await this._request("", undefined, url, undefined, data)).body)
    }

    /**
     * 创建一个文件的分享链接
     * @param file_ids 要分享的文件fid列表
     * @param pwd 分享密码，没有则没有密码,密码为4位字母数字
     */
    share(file_ids: number[], pwd: string | null = null) {
        let data: any = {
            fid_list: JSON.stringify(file_ids),
            schannel: 0,
            channel_list: JSON.stringify([])
        }
        if (pwd) {
            if (!pwd.match(/[0-9a-zA-Z]{4}/g)) {
                throw new Error("share pwd should match reg [0-9a-zA-Z]{4}")
            }
            data.pwd = pwd
            data.schannel = 4
        }
        let url = 'http://pan.baidu.com/share/set'
        return this._request('share/set', '', url, undefined, data)
    }

    /**
     *  添加离线任务，支持所有百度网盘支持的类型
     * @param source_url 离线下载目标的URL
     * @param remote_path 欲保存到百度网盘的目录, 注意以 / 打头
     * @param selected_idx 在 BT 或者磁力链的下载类型中, 选择哪些idx下载, 不填写为全部
     */
    add_download_task(source_url: string, remote_path: string, selected_idx: string[] = []) {
        if (source_url.startsWith("magnet:?")) {
            return this.add_magnet_task(source_url, remote_path, selected_idx)
        } else if (source_url.endsWith(".torrent")) {
            return this.add_torrent_task(source_url, remote_path, selected_idx)
        } else {
            let data = {
                'method': 'add_task',
                'source_url': source_url,
                'save_path': remote_path,
            }
            let url = `http://${BAIDUPAN_SERVER}/rest/2.0/services/cloud_dl`
            return this._request('services/cloud_dl', "add_task", url, undefined, data)
        }
    }

    async add_magnet_task(magnet: string, remote_path: string, selected_idx: string[] = []) {
        let response = JSON.parse((await this._get_magnet_info(magnet)).body)
        if (response.error_code) {
            throw new Error("add margnet task failed:" + response.error_code)
        }
        if (!response.margnet_info) {
            throw new Error("add margnet task failed:no margnet info")
        }
        let selected_idx_: string
        if (selected_idx.length > 0) {
            selected_idx_ = selected_idx.join(',')
        } else {
            selected_idx_ = (response.margnet_info as string[]).join(',')
        }
        let data = {
            'source_url': magnet,
            'save_path': remote_path,
            'selected_idx': selected_idx_,
            'task_from': '1',
            'type': '4'  // 4 is magnet
        }
        let url = `http://${BAIDUPAN_SERVER}/rest/2.0/services/cloud_dl`
        return this._request('create', 'add_task', url, undefined, data, undefined, { timeout: 30 })
    }

    _get_magnet_info(magnet: string) {
        let data = {
            'source_url': magnet,
            'save_path': '/',
            'type': '4'  // 4 is magnet
        }
        let url = `http://${BAIDUPAN_SERVER}/rest/2.0/services/cloud_dl`
        return this._request('cloud_dl', 'query_magnetinfo', url, undefined, data, undefined, { timeout: 30 })
    }

    /**
     * 添加本地BT任务
     * @param torrent_path 本地种子的路径
     * @param save_path 远程保存路径
     * @param selected_idx 要下载的文件序号 —— 集合为空下载所有，非空集合指定序号集合，空串下载默认
     */
    async add_torrent_task(torrent_path: string, save_path = '/', selected_idx: string[] = []) {
        let readstream = fs.createReadStream(torrent_path)
        let basename = path.basename(torrent_path)
        await this.delete([`/${basename}`])
        let response = JSON.parse((await this.upload(`/${basename}`, readstream)).body)
        let remote_path = response.path
        response = JSON.parse((await this._get_torrent_info(remote_path)).body)
        if (response.error_code) {
            throw new Error("add_torrent_task failed because get_torrent_info failed:" + response.error_code)
        }
        if (!response.torrent_info.file_info) {
            throw new Error("add_torrent_task failed because no torrent_info.file_info")
        }
        let selected_idx_: string
        if (selected_idx.length > 0) {
            selected_idx_ = selected_idx.join(',')
        } else {
            selected_idx_ = (response.margnet_info as string[]).join(',')
        }
        let data = {
            'file_sha1': response['torrent_info']['sha1'],
            'save_path': save_path,
            'selected_idx': selected_idx,
            'task_from': '1',
            'source_path': remote_path,
            'type': '2'  // 2 is torrent file
        }
        let url = `http://${BAIDUPAN_SERVER}/rest/2.0/services/cloud_dl`
        return this._request('create', 'add_task', url, undefined, data)
    }

    _get_torrent_info(torrent_path: string) {
        let data = {
            'source_path': torrent_path,
            'type': '2'  // 2 is torrent
        }
        let url = `http://${BAIDUPAN_SERVER}/rest/2.0/services/cloud_dl`
        return this._request('cloud_dl', 'query_sinfo', url, undefined, data, undefined, { timeout: 30 })

    }

    /**
     * 根据任务ID号，查询离线下载任务信息及进度信息
     * @param task_ids 要查询的任务ID
     * @param operate_type 0:查任务信息,1:查进度信息
     */
    query_download_tasks(task_ids: string[], operate_type: 0 | 1 = 1) {
        let params = {
            task_ids: task_ids.join(","),
            op_type: operate_type
        }
        let url = `http://${BAIDUPAN_SERVER}/rest/2.0/services/cloud_dl`
        return this._request('services/cloud_dl', 'query_task', url, params)
    }

    /**
     * 查询离线下载任务ID列表及任务信息.
     * @param need_task_info 是否需要返回任务信息 0:不需要,1:需要
     * @param asc 0:降序,1:升序
     * @param start 查询任务起始位置
     * @param create_time 任务创建时间，默认为空
     * @param limit 设定返回任务数量，默认为10
     * @param status 任务状态，默认为空  
     * 0:下载成功  
     * 1:下载进行中  
     * 2:系统错误  
     * 3:资源不存在  
     * 4:下载超时  
     * 5:资源存在但下载失败  
     * 6:存储空间不足  
     * 7:目标地址数据已存在  
     * 8:任务取消  
     * @param source_url 源地址URL
     * @param remote_path 文件保存路径
     */
    list_download_tasks(need_task_info: "0" | "1" = "1", asc: "0" | "1" = "0", start = 0, create_time: number | null = null, limit = 10, status: number = 255, source_url: string | null = null, remote_path: string | null = null) {
        let params = {
            'start': start,
            'limit': limit,
            'status': status,
            'need_task_info': need_task_info,
            'asc': asc,
            'source_url': source_url,
            'remote_path': remote_path,
            'create_time': create_time
        }
        let url = `http://${BAIDUPAN_SERVER}/rest/2.0/services/cloud_dl`
        return this._request("services/cloud_dl", "list_task", url, params)
    }

    download(remote_path: string, to: NodeJS.WritableStream, headers: any = null) {
        let params = { path: remote_path }
        let url = `https://${BAIDUPCS_SERVER}/rest/2.0/pcs/file`
        return new Promise<requests.Response>((resolve, reject) => {
            this.__request('file', (err, resp) => {
                if (err) reject(err)
                else resolve(resp)
            }, 'download', url, params).pipe(to)
        })
    }

    /**
     * 上传单个文件（<2G）
     * @param dest_file  网盘中文件的保存路径（含文件名）
     * @param file 上传的内容
     */
    upload(dest_file: string, file: NodeJS.ReadableStream) {
        let params = {
            'path': dest_file,
        }
        let url = `https://${BAIDUPCS_SERVER}/rest/2.0/pcs/file`
        return this._request('file', 'upload', url, params, undefined, file)
    }

    /**
     * 分片上传—文件分片及上传.
     * 百度 PCS 服务支持每次直接上传最大2G的单个文件。
     * 
     * 如需支持上传超大文件（>2G），则可以通过组合调用分片文件上传的
     * ``upload_tmpfile`` 方法和 ``upload_superfile`` 方法实现：
     * 
     * 1. 首先，将超大文件分割为2G以内的单文件，并调用 ``upload_tmpfile``
     * 分片文件依次上传；
     * 2. 其次，调用 ``upload_superfile`` ，完成分片文件的重组。
     * 
     * 除此之外，如果应用中需要支持断点续传的功能，
     * 也可以通过分片上传文件并调用 ``upload_superfile`` 接口的方式实现。
     * @param file 上传的内容
     */
    upload_tmpfile(file: NodeJS.ReadableStream) {
        let params = {
            'type': 'tmpfile',
        }
        let url = `https://${BAIDUPCS_SERVER}/rest/2.0/pcs/file`
        return this._request('file', 'upload', url, params, undefined, file)
    }

    upload_superfile(remote_path: string, block_list: string[]) {
        let params = { path: remote_path }
        let data = {
            'param': JSON.stringify({ block_list: block_list })
        }
        let url = `https://${BAIDUPCS_SERVER}/rest/2.0/pcs/file`
        return this._request("file", 'createsuperfile', url, params, data)
    }
}

let login_err: {
    [id: string]: {
        msg: string,
        field: string
    }
} = {
    "-1": {
        msg: '系统错误,请您稍后再试,<a href="http://passport.baidu.com/v2/?ucenterfeedback#{urldata}#login"  target="_blank">帮助中心</a>',
        field: ""
    },
    1: {
        msg: "您输入的帐号格式不正确",
        field: "userName"
    },
    2: {
        msg: '用户名或密码有误，请重新输入或<a href="http://passport.baidu.com/?getpassindex#{urldata}"  target="_blank" >找回密码</a>',
        field: "userName"
    },
    3: {
        msg: "验证码不存在或已过期,请重新输入",
        field: ""
    },
    4: {
        msg: "帐号或密码错误，请重新输入或者<a href='http://passport.baidu.com/?getpassindex#{urldata}'  target='_blank' >找回密码</a>",
        field: "password"
    },
    5: {
        msg: "",
        field: ""
    },
    6: {
        msg: "您输入的验证码有误",
        field: "verifyCode"
    },
    7: {
        msg: "用户名或密码有误，请重新输入或<a href='http://passport.baidu.com/?getpassindex#{urldata}'  target='_blank' >找回密码</a>",
        field: "password"
    },
    16: {
        msg: '您的帐号因安全问题已被限制登录,<a href="http://passport.baidu.com/v2/?ucenterfeedback#{urldata}#login"  target="_blank" >帮助中心</a>',
        field: ""
    },
    257: {
        msg: "请输入验证码",
        field: "verifyCode"
    },
    100027: {
        msg: "百度正在进行系统升级，暂时不能提供服务，敬请谅解",
        field: ""
    },
    120016: {
        msg: "",
        field: ""
    },
    18: {
        msg: "",
        field: ""
    },
    19: {
        msg: "",
        field: ""
    },
    20: {
        msg: "",
        field: ""
    },
    21: {
        msg: "没有登录权限",
        field: ""
    },
    22: {
        msg: "",
        field: ""
    },
    23: {
        msg: "",
        field: ""
    },
    24: {
        msg: "百度正在进行系统升级，暂时不能提供服务，敬请谅解",
        field: ""
    },
    400031: {
        msg: "请在弹出的窗口操作,或重新登录",
        field: ""
    },
    400032: {
        msg: "",
        field: ""
    },
    400034: {
        msg: "",
        field: ""
    },
    401007: {
        msg: "您的手机号关联了其他帐号，请选择登录",
        field: ""
    },
    120021: {
        msg: "登录失败,请在弹出的窗口操作,或重新登录",
        field: ""
    },
    500010: {
        msg: "登录过于频繁,请24小时后再试",
        field: ""
    },
    200010: {
        msg: "验证码不存在或已过期",
        field: ""
    },
    100005: {
        msg: "系统错误,请您稍后再试",
        field: ""
    },
    120019: {
        msg: "请在弹出的窗口操作,或重新登录",
        field: "userName"
    },
    110024: {
        msg: "此帐号暂未激活,<a href='#{gotourl}' >重发验证邮件</a>",
        field: ""
    },
    100023: {
        msg: "开启Cookie之后才能登录,<a href='http://passport.baidu.com/v2/?ucenterfeedback#{urldata}#login'  target='_blank' >如何开启</a>?",
        field: ""
    },
    17: {
        msg: '您的帐号已锁定,请<a href="http://passport.baidu.com/v2/?ucenterfeedback#login_10" target="_blank">解锁</a>后登录',
        field: "userName"
    },
    400401: {
        msg: "",
        field: ""
    },
    400037: {
        msg: "",
        field: ""
    },
    50023: {
        msg: "1个手机号30日内最多换绑3个账号",
        field: ""
    },
    50024: {
        msg: "注册过于频繁，请稍候再试",
        field: ""
    },
    50025: {
        msg: "注册过于频繁，请稍候再试；也可以通过上行短信的方式进行注册",
        field: ""
    },
    50028: {
        msg: '帐号或密码多次输错，请3个小时之后再试或<a href="http://passport.baidu.com/?getpassindex&getpassType=financePwdError#{urldata}"  target="_blank">找回密码</a>',
        field: ""
    },
    50029: {
        msg: '帐号或密码多次输错，请3个小时之后再试或<a href="http://passport.baidu.com/?getpassindex&getpassType=pwdError#{urldata}"  target="_blank">找回密码</a>',
        field: ""
    },
    50030: {
        msg: "抱歉，该手机号的申请次数已达当日上限，请更换手机号",
        field: ""
    },
    50031: {
        msg: "抱歉，该手机号的申请次数已达当月上限，请更换手机号",
        field: ""
    },
    50032: {
        msg: "抱歉，该手机号的申请次数已达本季度上限，请更换手机号",
        field: ""
    },
    400413: {
        msg: "",
        field: ""
    },
    400414: {
        msg: "",
        field: ""
    },
    400415: {
        msg: "帐号存在风险，为了您的帐号安全，请到百度钱包/理财/地图任一APP登录并完成验证，谢谢",
        field: ""
    },
    400500: {
        msg: "您登录的帐号已注销，请登录其他帐号或重新注册",
        field: ""
    },
    72200: {
        msg: "您的帐号因冻结暂时无法登录，请前往冻结时的手机APP，在登录页点击遇到问题进行解冻",
        field: ""
    },
    96001: {
        msg: "您的帐号因违反百度用户协议被限制登录",
        field: ""
    }
}