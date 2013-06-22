#include <v8.h>
#include <uv.h>
#include <node.h>
#include <node_buffer.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypto_box.h>
#include <crypto_sign.h>

using namespace std;
using namespace node;
using namespace v8;

static Handle<Value> node_crypto_box (const Arguments&);
static Handle<Value> node_crypto_box_open (const Arguments&);
static Handle<Value> node_crypto_box_keypair (const Arguments&);

static Handle<Value> node_crypto_sign (const Arguments&);
static Handle<Value> node_crypto_sign_open (const Arguments&);
static Handle<Value> node_crypto_sign_keypair (const Arguments&);


static string buf_to_str (Handle<Object> b) {
    return string(Buffer::Data(b), Buffer::Length(b));
}

static Buffer* str_to_buf (string s) {
    Buffer* res = Buffer::New(s.length());
    memcpy(Buffer::Data(res), s.c_str(), s.length());
    return res;
}

struct BoxRequest {
    uv_work_t request;
    Persistent<Function> callback;
    
    bool open, success;
    string m, n, pk, sk;

    string c, err;
};

static void BoxAsync(uv_work_t *req) {
    BoxRequest *boxreq = static_cast<BoxRequest*>(req->data);
    try {
        if(!boxreq->open) {
            boxreq->c = crypto_box(boxreq->m, boxreq->n, boxreq->pk, boxreq->sk);
        } else {
            boxreq->c = crypto_box_open(boxreq->m, boxreq->n, boxreq->pk, boxreq->sk);
        }
        boxreq->success = true;
    } catch(const char *e) {
        boxreq->err = string(e);
    }
}

static void BoxAsyncAfter(uv_work_t *req, int n) {
    BoxRequest *boxreq = static_cast<BoxRequest*>(req->data);

    Handle<Value> argv[2];
    if(boxreq->success) {
        argv[0] = Null();
        argv[1] = str_to_buf(boxreq->c)->handle_;
    } else {
        argv[0] = String::New(boxreq->err.c_str());
        argv[1] = Null();
    }

    boxreq->callback->Call(Context::GetCurrent()->Global(),
        2, argv);
    boxreq->callback.Dispose();
    delete boxreq;
}

static Handle<Value> node_crypto_box (const Arguments& args) {
    Handle<Function> cb = Handle<Function>::Cast(args[4]);

    BoxRequest *boxreq = new BoxRequest();
    boxreq->request.data = boxreq;
    boxreq->callback = Persistent<Function>::New(cb);

    boxreq->open = false;
    boxreq->m = buf_to_str(args[0]->ToObject());
    boxreq->n = buf_to_str(args[1]->ToObject());
    boxreq->pk = buf_to_str(args[2]->ToObject());
    boxreq->sk = buf_to_str(args[3]->ToObject());

    uv_queue_work(uv_default_loop(), &boxreq->request,
        BoxAsync, BoxAsyncAfter);

    return Undefined();
}

static Handle<Value> node_crypto_box_open (const Arguments& args) {
    Handle<Function> cb = Handle<Function>::Cast(args[4]);

    BoxRequest *boxreq = new BoxRequest();
    boxreq->request.data = boxreq;
    boxreq->callback = Persistent<Function>::New(cb);

    boxreq->open = true;
    boxreq->m = buf_to_str(args[0]->ToObject());
    boxreq->n = buf_to_str(args[1]->ToObject());
    boxreq->pk = buf_to_str(args[2]->ToObject());
    boxreq->sk = buf_to_str(args[3]->ToObject());

    uv_queue_work(uv_default_loop(), &boxreq->request,
        BoxAsync, BoxAsyncAfter);

/*
    return Undefined();
    HandleScope scope;
    string c = buf_to_str(args[0]->ToObject());
    string n = buf_to_str(args[1]->ToObject());
    string pk = buf_to_str(args[2]->ToObject());
    string sk = buf_to_str(args[3]->ToObject());
    try {
        string m = crypto_box_open(c,n,pk,sk);
        return scope.Close(str_to_buf(m)->handle_);
    } catch(...) {
        return scope.Close(Null());
    }
    */
}

static Handle<Value> node_crypto_box_keypair (const Arguments& args) {
    HandleScope scope;
    string sk;
    Buffer* pk_buf = str_to_buf(crypto_box_keypair(&sk));
    Buffer* sk_buf = str_to_buf(sk);
    Local<Array> res = Array::New(2);
    res->Set(0, pk_buf->handle_);
    res->Set(1, sk_buf->handle_);
    return scope.Close(res);
}

static Handle<Value> node_crypto_sign (const Arguments& args) {
    HandleScope scope;
    string m = buf_to_str(args[0]->ToObject());
    string sk = buf_to_str(args[1]->ToObject());
    try {
        string sm = crypto_sign(m,sk);
        return scope.Close(str_to_buf(sm)->handle_);
    } catch(...) {
        return scope.Close(Null());
    }
}

static Handle<Value> node_crypto_sign_open (const Arguments& args) {
    HandleScope scope;
    string sm = buf_to_str(args[0]->ToObject());
    string pk = buf_to_str(args[1]->ToObject());
    try {
        string m = crypto_sign_open(sm,pk);
        return scope.Close(str_to_buf(m)->handle_);
    } catch(...) {
        return scope.Close(Null());
    }
}

static Handle<Value> node_crypto_sign_keypair (const Arguments& args) {
    HandleScope scope;
    string sk;
    Buffer* pk_buf = str_to_buf(crypto_sign_keypair(&sk));
    Buffer* sk_buf = str_to_buf(sk);
    Local<Array> res = Array::New(2);
    res->Set(0, pk_buf->handle_);
    res->Set(1, sk_buf->handle_);
    return scope.Close(res);
}


void init (Handle<Object> target) {
    HandleScope scope;

    NODE_SET_METHOD(target, "box", node_crypto_box);
    NODE_SET_METHOD(target, "box_open", node_crypto_box_open);
    NODE_SET_METHOD(target, "box_keypair", node_crypto_box_keypair);

    NODE_SET_METHOD(target, "sign", node_crypto_sign);
    NODE_SET_METHOD(target, "sign_open", node_crypto_sign_open);
    NODE_SET_METHOD(target, "sign_keypair", node_crypto_sign_keypair);

    target->Set(String::NewSymbol("box_NONCEBYTES"), Integer::New(crypto_box_NONCEBYTES));
    target->Set(String::NewSymbol("box_PUBLICKEYBYTES"), Integer::New(crypto_box_PUBLICKEYBYTES));
    target->Set(String::NewSymbol("box_SECRETKEYBYTES"), Integer::New(crypto_box_SECRETKEYBYTES));

    target->Set(String::NewSymbol("sign_PUBLICKEYBYTES"), Integer::New(crypto_sign_PUBLICKEYBYTES));
    target->Set(String::NewSymbol("sign_SECRETKEYBYTES"), Integer::New(crypto_sign_SECRETKEYBYTES));
}
NODE_MODULE(nacl, init)
