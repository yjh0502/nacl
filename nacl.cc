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
static Handle<Value> nacl_box_open (const Arguments&);
static Handle<Value> nacl_box_keypair (const Arguments&);

static Handle<Value> nacl_secretbox (const Arguments&);
static Handle<Value> nacl_secretbox_open (const Arguments&);

static Handle<Value> nacl_sign (const Arguments&);
static Handle<Value> nacl_sign_open (const Arguments&);
static Handle<Value> nacl_sign_keypair (const Arguments&);


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
    SecretBox,
    SecretBoxOpen,
};

struct BoxRequest {
    uv_work_t request;
    Persistent<Function> callback;
    
    BoxType type;
    string m, n, pk, sk;

    bool success;
    string c, err;
};

static void calc(BoxRequest *boxreq) {
    try {
        switch(boxreq->type) {
        case Box:
            boxreq->c = crypto_box(boxreq->m, boxreq->n, boxreq->pk, boxreq->sk);
            break;
        case BoxOpen:
            boxreq->c = crypto_box_open(boxreq->m, boxreq->n, boxreq->pk, boxreq->sk);
            break;
        case SecretBox:
            boxreq->c = crypto_secretbox(boxreq->m, boxreq->n, boxreq->sk);
            break;
        case SecretBoxOpen:
            boxreq->c = crypto_secretbox_open(boxreq->m, boxreq->n, boxreq->sk);
            break;
        }

        boxreq->success = true;
    } catch(const char *e) {
        boxreq->err = string(e);
    }
}

static Handle<Value> returnval(BoxRequest *boxreq) {
    if(boxreq->success) {
        return str_to_buf(boxreq->c)->handle_;
    } else {
        return String::New(boxreq->err.c_str());
    }
}

static void BoxAsync(uv_work_t *req) {
    BoxRequest *boxreq = static_cast<BoxRequest*>(req->data);
    calc(boxreq);
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

static void fillReqPublic(const Arguments& args, BoxRequest *boxreq, BoxType type) {
    boxreq->type = type;
    boxreq->m = buf_to_str(args[0]->ToObject());
    boxreq->n = buf_to_str(args[1]->ToObject());
    boxreq->pk = buf_to_str(args[2]->ToObject());
    boxreq->sk = buf_to_str(args[3]->ToObject());

    Handle<Function> cb = Handle<Function>::Cast(args[4]);
    boxreq->request.data = boxreq;
    boxreq->callback = Persistent<Function>::New(cb);
}

static void fillReqSecret(const Arguments& args, BoxRequest *boxreq, BoxType type) {
    boxreq->type = type;
    boxreq->m = buf_to_str(args[0]->ToObject());
    boxreq->n = buf_to_str(args[1]->ToObject());
    boxreq->sk = buf_to_str(args[2]->ToObject());

    Handle<Function> cb = Handle<Function>::Cast(args[3]);
    boxreq->request.data = boxreq;
    boxreq->callback = Persistent<Function>::New(cb);
}

static Handle<Value> nacl_box (const Arguments& args) {
    BoxRequest *boxreq = new BoxRequest();
    fillReqPublic(args, boxreq, Box);

    uv_queue_work(uv_default_loop(), &boxreq->request,
        BoxAsync, BoxAsyncAfter);

    return Undefined();
}

static Handle<Value> nacl_box_open (const Arguments& args) {
    BoxRequest *boxreq = new BoxRequest();
    fillReqPublic(args, boxreq, BoxOpen);

    uv_queue_work(uv_default_loop(), &boxreq->request,
        BoxAsync, BoxAsyncAfter);

    return Undefined();
}

static Handle<Value> nacl_box_sync (const Arguments& args) {
    BoxRequest *boxreq = new BoxRequest();
    fillReqPublic(args, boxreq, Box);
    calc(boxreq);
    return returnval(boxreq);
}

static Handle<Value> nacl_box_open_sync (const Arguments& args) {
    BoxRequest *boxreq = new BoxRequest();
    fillReqPublic(args, boxreq, BoxOpen);
    calc(boxreq);
    return returnval(boxreq);
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

static Handle<Value> nacl_secretbox (const Arguments& args) {
    BoxRequest *boxreq = new BoxRequest();
    fillReqSecret(args, boxreq, SecretBox);

    uv_queue_work(uv_default_loop(), &boxreq->request,
        BoxAsync, BoxAsyncAfter);

    return Undefined();
}

static Handle<Value> nacl_secretbox_open (const Arguments& args) {
    BoxRequest *boxreq = new BoxRequest();
    fillReqSecret(args, boxreq, SecretBoxOpen);

    uv_queue_work(uv_default_loop(), &boxreq->request,
        BoxAsync, BoxAsyncAfter);

    return Undefined();
}

static Handle<Value> nacl_secretbox_sync (const Arguments& args) {
    BoxRequest *boxreq = new BoxRequest();
    fillReqSecret(args, boxreq, SecretBox);

    calc(boxreq);
    return returnval(boxreq);
}

static Handle<Value> nacl_secretbox_open_sync (const Arguments& args) {
    BoxRequest *boxreq = new BoxRequest();
    fillReqSecret(args, boxreq, SecretBoxOpen);

    calc(boxreq);
    return returnval(boxreq);
}


static Handle<Value> nacl_sign (const Arguments& args) {
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

static Handle<Value> nacl_sign_open (const Arguments& args) {
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


void init (Handle<Object> target) {
    HandleScope scope;

    NODE_SET_METHOD(target, "box", nacl_box);
    NODE_SET_METHOD(target, "box_open", nacl_box_open);

    NODE_SET_METHOD(target, "box_sync", nacl_box_sync);
    NODE_SET_METHOD(target, "box_open_sync", nacl_box_open_sync);

    NODE_SET_METHOD(target, "box_keypair", nacl_box_keypair);

    NODE_SET_METHOD(target, "secretbox", nacl_secretbox);
    NODE_SET_METHOD(target, "secretbox_open", nacl_secretbox_open);

    NODE_SET_METHOD(target, "secretbox_sync", nacl_secretbox_sync);
    NODE_SET_METHOD(target, "secretbox_open_sync", nacl_secretbox_open_sync);

    NODE_SET_METHOD(target, "sign", nacl_sign);
    NODE_SET_METHOD(target, "sign_open", nacl_sign_open);
    NODE_SET_METHOD(target, "sign_keypair", nacl_sign_keypair);

    target->Set(String::NewSymbol("box_NONCEBYTES"),
        Integer::New(crypto_box_NONCEBYTES));
    target->Set(String::NewSymbol("box_PUBLICKEYBYTES"),
        Integer::New(crypto_box_PUBLICKEYBYTES));
    target->Set(String::NewSymbol("box_SECRETKEYBYTES"),
        Integer::New(crypto_box_SECRETKEYBYTES));

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
