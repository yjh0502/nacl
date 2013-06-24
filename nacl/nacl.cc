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

enum BoxType {
    Box,
    BoxOpen,
    Sign,
    SignOpen,

    SecretBox,
    SecretBoxOpen,
};

struct NaclReq {
    uv_work_t request;
    Persistent<Function> callback;
    
    BoxType type;
    string m, n, pk, sk;

    bool success;
    string c, err;

    void process();
    Handle<Value> returnVal();
    static NaclReq* New(const Arguments& args, BoxType type);
};

void NaclReq::process() {
    try {
        switch(this->type) {
        case Box:
            this->c = crypto_box(this->m, this->n, this->pk, this->sk);
            break;
        case BoxOpen:
            this->c = crypto_box_open(this->m, this->n, this->pk, this->sk);
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

NaclReq *NaclReq::New(const Arguments &args, BoxType type) {
    HandleScope scope;
    NaclReq *req = new NaclReq();
    req->type = type;

    int callbackIndex = 0;
    switch(type) {
    case Box:
    case BoxOpen:
        req->m = buf_to_str(args[0]->ToObject());
        req->n = buf_to_str(args[1]->ToObject());
        req->pk = buf_to_str(args[2]->ToObject());
        req->sk = buf_to_str(args[3]->ToObject());
        callbackIndex = 4;
        break;

    case Sign:
    case SignOpen:
        req->m = buf_to_str(args[0]->ToObject());
        req->sk = buf_to_str(args[1]->ToObject());
        callbackIndex = 2;
        break;

    case SecretBox:
    case SecretBoxOpen:
        req->m = buf_to_str(args[0]->ToObject());
        req->n = buf_to_str(args[1]->ToObject());
        req->sk = buf_to_str(args[2]->ToObject());
        callbackIndex = 3;
        break;
    }

    Handle<Function> cb = Handle<Function>::Cast(args[callbackIndex]);
    req->request.data = req;
    req->callback = Persistent<Function>::New(cb);

    return req;
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

static Handle<Value> nacl_box (const Arguments& args) {
    HandleScope scope;
    NaclReq *req = NaclReq::New(args, Box);
    uv_queue_work(uv_default_loop(), &req->request, HandleReqAsync, HandleReqAsyncAfter);
    return Undefined();
}

static Handle<Value> nacl_box_sync (const Arguments& args) {
    NaclReq *req = NaclReq::New(args, Box);
    req->process();
    return req->returnVal();
}

static Handle<Value> nacl_box_open (const Arguments& args) {
    HandleScope scope;
    NaclReq *req = NaclReq::New(args, BoxOpen);
    uv_queue_work(uv_default_loop(), &req->request, HandleReqAsync, HandleReqAsyncAfter);
    return Undefined();
}

static Handle<Value> nacl_box_open_sync (const Arguments& args) {
    HandleScope scope;
    NaclReq *req = NaclReq::New(args, BoxOpen);
    req->process();
    return req->returnVal();
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
    HandleScope scope;
    NaclReq *req = NaclReq::New(args, Sign);
    uv_queue_work(uv_default_loop(), &req->request, HandleReqAsync, HandleReqAsyncAfter);
    return Undefined();
}

static Handle<Value> nacl_sign_sync (const Arguments& args) {
    NaclReq *req = NaclReq::New(args, Sign);
    req->process();
    return req->returnVal();
}

static Handle<Value> nacl_sign_open (const Arguments& args) {
    HandleScope scope;
    NaclReq *req = NaclReq::New(args, SignOpen);
    uv_queue_work(uv_default_loop(), &req->request, HandleReqAsync, HandleReqAsyncAfter);
    return Undefined();
}

static Handle<Value> nacl_sign_open_sync (const Arguments& args) {
    HandleScope scope;
    NaclReq *req = NaclReq::New(args, SignOpen);
    req->process();
    return req->returnVal();
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
    NaclReq *req = NaclReq::New(args, SecretBox);
    uv_queue_work(uv_default_loop(), &req->request,
        HandleReqAsync, HandleReqAsyncAfter);

    return Undefined();
}

static Handle<Value> nacl_secretbox_open (const Arguments& args) {
    NaclReq *req = NaclReq::New(args, SecretBoxOpen);
    uv_queue_work(uv_default_loop(), &req->request,
        HandleReqAsync, HandleReqAsyncAfter);

    return Undefined();
}

static Handle<Value> nacl_secretbox_sync (const Arguments& args) {
    NaclReq *req = NaclReq::New(args, SecretBox);
    req->process();
    return req->returnVal();
}

static Handle<Value> nacl_secretbox_open_sync (const Arguments& args) {
    NaclReq *req = NaclReq::New(args, SecretBoxOpen);
    req->process();
    return req->returnVal();
}


void init (Handle<Object> target) {
    HandleScope scope;

    NODE_SET_METHOD(target, "box", nacl_box);
    NODE_SET_METHOD(target, "box_open", nacl_box_open);
    NODE_SET_METHOD(target, "box_sync", nacl_box_sync);
    NODE_SET_METHOD(target, "box_open_sync", nacl_box_open_sync);
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