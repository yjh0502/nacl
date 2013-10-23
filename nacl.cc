#include <v8.h>
#include <uv.h>
#include <node.h>
#include <node_buffer.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <crypto_box.h>
#include <crypto_sign.h>
#include <crypto_secretbox.h>


// Zlib support
#include "miniz.c"

/** In-memory inflate/deflate implementation */
typedef int (*zlib_op)(mz_streamp strm, int flush);
#define CHUNK_SIZE (1024 * 4)

static int init_stream(z_stream *strm,
        const void *src, int srclen) {
    strm->total_in = strm->avail_in = srclen;
    strm->avail_out = CHUNK_SIZE;
    strm->next_in = (Bytef*) src;
    strm->next_out = (Bytef*) malloc(CHUNK_SIZE);

    return !strm->next_out;
}

static int zlib_loop(z_stream *strm, zlib_op op_func, char **buf, int *buflen) {
    char *out = (char *)strm->next_out;
    int outlen = strm->avail_out;

    int err, op = Z_NO_FLUSH;
    while((err = op_func(strm, op)) != Z_STREAM_END) {
        if(err != Z_OK)
            goto err;

        if(!strm->avail_in) {
            op = Z_FINISH;
            continue;
        }

        if(!(out = (char *)realloc(out, outlen << 1)))
            goto err;

        strm->next_out = (Bytef*)(out + outlen);
        strm->avail_out = outlen;
        outlen <<= 1;
    }

    *buf = out;
    *buflen = strm->total_out;
    return 0;

err:
    free(out);
    *buf = NULL;
    *buflen = 0;
    return -1;
}

int inflate_data(const void *src, int srclen, char **dest_out, int *destlen_out) {
    z_stream strm;
    memset(&strm, 0, sizeof(z_stream));
    if(init_stream(&strm, src, srclen))
        return -1;

    if(inflateInit(&strm) != Z_OK) {
        inflateEnd(&strm);
        return -1;
    }

    int err = zlib_loop(&strm, inflate, dest_out, destlen_out);
    inflateEnd(&strm);
    if(err) {
        return err;
    }

    return 0;
}

int deflate_data(const void *src, int srclen,
        char ** dest_out, int *destlen_out) {
    z_stream strm;
    memset(&strm, 0, sizeof(z_stream));
    if(init_stream(&strm, src, srclen))
        return -1;

    if(deflateInit(&strm, Z_DEFAULT_COMPRESSION) != Z_OK) {
        deflateEnd(&strm);
        return -1;
    }

    int err = zlib_loop(&strm, deflate, dest_out, destlen_out);
    deflateEnd(&strm);
    if(err) {
        return err;
    }

    return 0;
}


using namespace std;
using namespace node;
using namespace v8;

static Handle<Value> nacl_box (const Arguments&);
static Handle<Value> nacl_box_sync (const Arguments&);
static Handle<Value> nacl_box_open (const Arguments&);
static Handle<Value> nacl_box_open_sync (const Arguments&);
static Handle<Value> nacl_box_keypair (const Arguments&);

static Handle<Value> nacl_sign (const Arguments&);
static Handle<Value> nacl_sign_sync (const Arguments&);
static Handle<Value> nacl_sign_open (const Arguments&);
static Handle<Value> nacl_sign_open_sync (const Arguments&);
static Handle<Value> nacl_sign_keypair (const Arguments&);

static Handle<Value> nacl_secretbox (const Arguments&);
static Handle<Value> nacl_secretbox_open (const Arguments&);


static string buf_to_str (Handle<Object> b) {
    return string(Buffer::Data(b), Buffer::Length(b));
}

static Buffer* str_to_buf (string s) {
    Buffer* res = Buffer::New(s.length());
    memcpy(Buffer::Data(res), s.c_str(), s.length());
    return res;
}

enum NaclReqType {
    Box,
    BoxOpen,
    DeflateBox,
    InflateBoxOpen,
    Sign,
    SignOpen,

    SecretBox,
    SecretBoxOpen,
};

enum CallType {
    Sync,
    Async,
};

struct NaclReq {
    uv_work_t request;
    Persistent<Function> callback;
    
    NaclReqType type;
    string m, n, pk, sk;

    bool success;
    string c, err;

    void init(const Arguments&, NaclReqType, CallType);
    void process();
    Handle<Value> returnVal();
};

void NaclReq::process() {
    char *out;
    int out_len, err;
    try {
        switch(this->type) {
        case DeflateBox:
            // Deflate before box
            err = deflate_data(this->m.c_str(), this->m.length(), &out, &out_len);
            if(err) {
                this->err = "failed to deflate"; return;
            }
            this->m = string(out, out_len);
            //fallthrough
        case Box:
            this->c = crypto_box(this->m, this->n, this->pk, this->sk);
            break;
        case BoxOpen:
            this->c = crypto_box_open(this->m, this->n, this->pk, this->sk);
            //fallthrough
        case InflateBoxOpen:
            // Deflate before box
            err = inflate_data(this->c.c_str(), this->c.length(), &out, &out_len);
            if(err) {
                this->err = "failed to deflate"; return;
            }
            this->c = string(out, out_len);
            // Inflate before box_open
            break;
        case Sign:
            this->c = crypto_sign(this->m, this->sk);
            break;
        case SignOpen:
            this->c = crypto_sign_open(this->m, this->sk);
            break;
        case SecretBox:
            this->c = crypto_secretbox(this->m, this->n, this->sk);
            break;
        case SecretBoxOpen:
            this->c = crypto_secretbox_open(this->m, this->n, this->sk);
            break;
        }

        this->success = true;
    } catch(const char *e) {
        this->err = string(e);
    }
}

Handle<Value> NaclReq::returnVal() {
    if(this->success) {
        return str_to_buf(this->c)->handle_;
    } else {
        return String::New(this->err.c_str());
    }
}

static void HandleReqAsync(uv_work_t *req) {
    NaclReq *naclreq = static_cast<NaclReq*>(req->data);
    naclreq->process();
}

static void HandleReqAsyncAfter(uv_work_t *req, int n) {
    NaclReq *naclreq = static_cast<NaclReq*>(req->data);

    Handle<Value> argv[2];
    if(naclreq->success) {
        argv[0] = Null();
        argv[1] = str_to_buf(naclreq->c)->handle_;
    } else {
        argv[0] = String::New(naclreq->err.c_str());
        argv[1] = Null();
    }

    naclreq->callback->Call(Context::GetCurrent()->Global(),
        2, argv);
    naclreq->callback.Dispose();
    delete naclreq;
}

void NaclReq::init(const Arguments &args, NaclReqType type, CallType callType) {
    this->type = type;

    int callbackIndex = 0;
    switch(type) {
    case DeflateBox:
    case InflateBoxOpen:
    case Box:
    case BoxOpen:
        this->m = buf_to_str(args[0]->ToObject());
        this->n = buf_to_str(args[1]->ToObject());
        this->pk = buf_to_str(args[2]->ToObject());
        this->sk = buf_to_str(args[3]->ToObject());
        callbackIndex = 4;
        break;

    case Sign:
    case SignOpen:
        this->m = buf_to_str(args[0]->ToObject());
        this->sk = buf_to_str(args[1]->ToObject());
        callbackIndex = 2;
        break;

    case SecretBox:
    case SecretBoxOpen:
        this->m = buf_to_str(args[0]->ToObject());
        this->n = buf_to_str(args[1]->ToObject());
        this->sk = buf_to_str(args[2]->ToObject());
        callbackIndex = 3;
        break;
    }

    if(callType == Async) {
        Handle<Function> cb = Handle<Function>::Cast(args[callbackIndex]);
        this->request.data = this;
        this->callback = Persistent<Function>::New(cb);
        uv_queue_work(uv_default_loop(), &this->request, HandleReqAsync, HandleReqAsyncAfter);
    }
}

static Handle<Value> nacl_box (const Arguments& args) {
    NaclReq *req = new NaclReq();
    req->init(args, Box, Async);
    return Undefined();
}

static Handle<Value> nacl_box_sync (const Arguments& args) {
    NaclReq req;
    req.init(args, Box, Sync);
    req.process();
    return req.returnVal();
}

static Handle<Value> nacl_deflate_box (const Arguments& args) {
    NaclReq *req = new NaclReq();
    req->init(args, DeflateBox, Async);
    return Undefined();
}

static Handle<Value> nacl_deflate_box_sync (const Arguments& args) {
    NaclReq req;
    req.init(args, DeflateBox, Sync);
    req.process();
    return req.returnVal();
}

static Handle<Value> nacl_box_open (const Arguments& args) {
    NaclReq *req = new NaclReq();
    req->init(args, BoxOpen, Async);
    return Undefined();
}

static Handle<Value> nacl_box_open_sync (const Arguments& args) {
    NaclReq req;
    req.init(args, BoxOpen, Sync);
    req.process();
    return req.returnVal();
}

static Handle<Value> nacl_inflate_box_open (const Arguments& args) {
    NaclReq *req = new NaclReq();
    req->init(args, InflateBoxOpen, Async);
    return Undefined();
}

static Handle<Value> nacl_inflate_box_open_sync (const Arguments& args) {
    NaclReq req;
    req.init(args, InflateBoxOpen, Sync);
    req.process();
    return req.returnVal();
}


static Handle<Value> nacl_box_keypair (const Arguments& args) {
    HandleScope scope;
    string sk;
    Buffer* pk_buf = str_to_buf(crypto_box_keypair(&sk));
    Buffer* sk_buf = str_to_buf(sk);
    Local<Array> res = Array::New(2);
    res->Set(0, pk_buf->handle_);
    res->Set(1, sk_buf->handle_);
    return scope.Close(res);
}

static Handle<Value> nacl_sign (const Arguments& args) {
    NaclReq *req = new NaclReq();
    req->init(args, Sign, Async);
    return Undefined();
}

static Handle<Value> nacl_sign_sync (const Arguments& args) {
    NaclReq req;
    req.init(args, Sign, Sync);
    req.process();
    return req.returnVal();
}

static Handle<Value> nacl_sign_open (const Arguments& args) {
    NaclReq *req = new NaclReq();
    req->init(args, SignOpen, Async);
    return Undefined();
}

static Handle<Value> nacl_sign_open_sync (const Arguments& args) {
    NaclReq req;
    req.init(args, SignOpen, Sync);
    req.process();
    return req.returnVal();
}

static Handle<Value> nacl_sign_keypair (const Arguments& args) {
    HandleScope scope;
    string sk;
    Buffer* pk_buf = str_to_buf(crypto_sign_keypair(&sk));
    Buffer* sk_buf = str_to_buf(sk);
    Local<Array> res = Array::New(2);
    res->Set(0, pk_buf->handle_);
    res->Set(1, sk_buf->handle_);
    return scope.Close(res);
}

static Handle<Value> nacl_secretbox (const Arguments& args) {
    NaclReq *req = new NaclReq();
    req->init(args, SecretBox, Async);
    return Undefined();
}

static Handle<Value> nacl_secretbox_open (const Arguments& args) {
    NaclReq *req = new NaclReq();
    req->init(args, SecretBoxOpen, Async);
    return Undefined();
}

static Handle<Value> nacl_secretbox_sync (const Arguments& args) {
    NaclReq req;
    req.init(args, SecretBox, Sync);
    req.process();
    return req.returnVal();
}

static Handle<Value> nacl_secretbox_open_sync (const Arguments& args) {
    NaclReq req;
    req.init(args, SecretBoxOpen, Sync);
    req.process();
    return req.returnVal();
}


void init (Handle<Object> target) {
    HandleScope scope;

    NODE_SET_METHOD(target, "box", nacl_box);
    NODE_SET_METHOD(target, "box_open", nacl_box_open);
    NODE_SET_METHOD(target, "box_sync", nacl_box_sync);
    NODE_SET_METHOD(target, "box_open_sync", nacl_box_open_sync);

    NODE_SET_METHOD(target, "deflate_box", nacl_deflate_box);
    NODE_SET_METHOD(target, "inflate_box_open", nacl_inflate_box_open);
    NODE_SET_METHOD(target, "deflate_box_sync", nacl_deflate_box_sync);
    NODE_SET_METHOD(target, "inflate_box_open_sync", nacl_inflate_box_open_sync);

    NODE_SET_METHOD(target, "box_keypair", nacl_box_keypair);

    NODE_SET_METHOD(target, "sign", nacl_sign);
    NODE_SET_METHOD(target, "sign_sync", nacl_sign_sync);
    NODE_SET_METHOD(target, "sign_open", nacl_sign_open);
    NODE_SET_METHOD(target, "sign_open_sync", nacl_sign_open_sync);
    NODE_SET_METHOD(target, "sign_keypair", nacl_sign_keypair);

    NODE_SET_METHOD(target, "secretbox", nacl_secretbox);
    NODE_SET_METHOD(target, "secretbox_open", nacl_secretbox_open);
    NODE_SET_METHOD(target, "secretbox_sync", nacl_secretbox_sync);
    NODE_SET_METHOD(target, "secretbox_open_sync", nacl_secretbox_open_sync);

    target->Set(String::NewSymbol("box_NONCEBYTES"),
        Integer::New(crypto_box_NONCEBYTES));
    target->Set(String::NewSymbol("box_PUBLICKEYBYTES"),
        Integer::New(crypto_box_PUBLICKEYBYTES));
    target->Set(String::NewSymbol("box_SECRETKEYBYTES"),
        Integer::New(crypto_box_SECRETKEYBYTES));

    target->Set(String::NewSymbol("sign_PUBLICKEYBYTES"),
        Integer::New(crypto_sign_PUBLICKEYBYTES));
    target->Set(String::NewSymbol("sign_SECRETKEYBYTES"),
        Integer::New(crypto_sign_SECRETKEYBYTES));

    target->Set(String::NewSymbol("secretbox_NONCEBYTES"),
        Integer::New(crypto_secretbox_NONCEBYTES));
    target->Set(String::NewSymbol("secretbox_KEYBYTES"),
        Integer::New(crypto_secretbox_KEYBYTES));

    target->Set(String::NewSymbol("sign_PUBLICKEYBYTES"),
        Integer::New(crypto_sign_PUBLICKEYBYTES));
    target->Set(String::NewSymbol("sign_SECRETKEYBYTES"),
        Integer::New(crypto_sign_SECRETKEYBYTES));
}
NODE_MODULE(nacl, init)
