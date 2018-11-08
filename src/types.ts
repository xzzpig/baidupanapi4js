import { type } from "os";

export interface PCSRequestResult {
    errno: number
    request_id: number
}

export interface ListFilesItem {
    category: number
    unlist: number
    fs_id: number
    oper_id: number
    server_ctime: number
    isdir: number
    local_mtime: number
    size: number
    server_filename: number
    share: number
    path: string
    local_ctime: number
    server_mtime: number
    md5?: string
}

export interface PCSListFilesResult extends PCSRequestResult {
    list: ListFilesItem[]
    guid_info: string
    guid: number
}

export interface PCSQuotaResult extends PCSRequestResult {
    used: number
    total: number
}

export interface PCSMkDirResult extends PCSRequestResult {
    fs_id: number
    path: string
    ctime: number
    mtime: number
    status: number
    isdir: number
    errno: number
    name: string
    category: number
}


export interface PathInfoItem {
    errno: number
    path: string
}

export interface PCSFileManagerResult extends PCSRequestResult {
    info: PathInfoItem[]
}
export type PCSDeleteResult = PCSFileManagerResult
export type PCSMoveResult = PCSFileManagerResult
export type PCSCopyResult = PCSFileManagerResult
export type PCSRenameResult = PCSFileManagerResult

export interface FileMeta {
    extent_tinyint4: number
    extent_tinyint1: number
    category: number
    fs_id: number
    ifhassubdir: number
    errno: number
    server_ctime: number
    path_md5: number
    oper_id: number
    local_mtime: number
    size: number
    server_mtime: number
    extent_int3: number
    share: number
    extent_tinyint3: number
    path: string
    local_ctime: number
    server_filename: number
    extent_tinyint2: number
    isdir: number
    dlink?: string
    tag?: number[]
    file_key?: string
    day?: string
    orientation?: string
    province?: string
    year?: string
    thumbs?: {
        icon: string
        url3: string
        url2: string
        url1: string
    }
    country?: string
    district?: string
    gid?: number
    mediaType?: string
    city?: string
    street?: string
    md5?: string
    month?: string
    lt_flag?: number
}

export interface PCSMetaResult extends PCSRequestResult {
    info: FileMeta[]
}

export type SearchItem = ListFilesItem

export interface PCSSearchResult extends PCSRequestResult {
    list: SearchItem[]
    has_more: number
}

export interface RecycleBinItem {
    fs_id: number
    server_filename: string
    server_mtime: number
    server_ctime: number
    local_mtime: number
    local_ctime: number
    isdir: number
    category: number
    share: number
    path: string
    leftTime: number
    size?: number
    md5?: string
}

export interface PCSListRecycleBinResult extends PCSRequestResult {
    list: SearchItem[]
    timestamp: number
}