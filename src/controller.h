#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>

#include <grpcpp/grpcpp.h>

#include "define.h"
#include "message.h"

#include "xnat.grpc.pb.h"

using namespace grpc;

struct config {
    std::string server_address;
    std::string ingress_ifname;
    std::string egress_ifname;
    std::string ipaddr;
    uint32_t vid;
    int verbose;
};

class XnatClient {
   public:
    XnatClient(std::shared_ptr<ChannelInterface> channel)
        : client_(XnatService::NewStub(channel)) {
    }

    int GetIngressInfo();
    int GetEgressInfo();

    int AddVip(const std::string &type,
               const std::string &ifname,
               uint32_t vid,
               const std::string &address);
    int DelVip();
    int AddVlanIface();
    int DelVlanIface(const std::string &type,
                     const std::string &ifname,
                     uint32_t vid);

   private:
    std::unique_ptr<XnatService::Stub> client_;
};

int
XnatClient::GetIngressInfo() {
    Empty request;
    Iface response;
    ClientContext context;

    Status status = client_->GetIngressInfo(&context, request, &response);

    if (status.ok()) {
        info("Ingress ifname %s", response.name().c_str());
    } else {
        err("error code(%d):%s %s",
            status.error_code(),
            status.error_message().c_str(),
            status.error_details().c_str());
        return ERROR;
    }

    return SUCCESS;
}

int
XnatClient::GetEgressInfo() {
    Empty request;
    Iface response;
    ClientContext context;

    Status status = client_->GetIngressInfo(&context, request, &response);

    if (status.ok()) {
        info("Egress ifname %s", response.name().c_str());
    } else {
        err("error code(%d):%s %s",
            status.error_code(),
            status.error_message().c_str(),
            status.error_details().c_str());
        return ERROR;
    }

    return SUCCESS;
}

int
XnatClient::AddVip(const std::string &type,
                   const std::string &ifname,
                   uint32_t vid,
                   const std::string &address) {
    Vip request;
    Bool response;
    ClientContext context;

    request.mutable_iface()->set_name(ifname);
    request.mutable_iface()->set_vid(vid);
    request.mutable_addr()->set_addr(address);

    if (type == "ingress") {
        request.set_type(INGRESS);
    }

    if (type == "egress") {
        request.set_type(EGRESS);
    }

    Status status = client_->AddVip(&context, request, &response);

    if (status.ok()) {
        if (response.success() == false) {
            return ERROR;
        }
        info("Add ip %s.%d: %s", ifname.c_str(), vid, address.c_str());
    } else {
        err("error code(%d):%s %s",
            status.error_code(),
            status.error_message().c_str(),
            status.error_details().c_str());
        return ERROR;
    }

    return SUCCESS;
}
int
XnatClient::DelVip() {
    return SUCCESS;
}
int
XnatClient::AddVlanIface() {
    return SUCCESS;
}

int
XnatClient::DelVlanIface(const std::string &type,
                         const std::string &ifname,
                         uint32_t vid) {
    Iface request;
    Bool response;
    ClientContext context;

    request.set_name(ifname);
    request.set_vid(vid);
    if (type == "ingress") {
        request.set_type(INGRESS);
    }
    if (type == "egress") {
        request.set_type(EGRESS);
    }

    Status status = client_->DelVlanIface(&context, request, &response);

    if (status.ok()) {
        if (response.success() == false) {
            return ERROR;
        }
        info("Delete vlan interface %s", ifname.c_str());
    } else {
        err("error code(%d):%s %s",
            status.error_code(),
            status.error_message().c_str(),
            status.error_details().c_str());
        return ERROR;
    }

    return SUCCESS;
}

class controller {
   public:
    controller(const struct config &config) : config_(config){};
    ~controller(){};

    int
    setup_grpc() {
        server_address_ = config_.server_address;
        client_         = std::make_unique<XnatClient>(XnatClient(
            CreateChannel(server_address_, InsecureChannelCredentials())));
        info("Connect to %s", server_address_.c_str());
        return SUCCESS;
    }

    int add_vip(const std::string &type,
                const std::string &ifname,
                uint32_t vid,
                const std::string &address);

    int del_vlan_iface(const std::string &type,
                       const std::string &ifname,
                       uint32_t vid);

   private:
    struct config config_;

    std::unique_ptr<XnatClient> client_;
    std::string server_address_;
};

int
controller::add_vip(const std::string &type,
                    const std::string &ifname,
                    uint32_t vid,
                    const std::string &address) {

    if (client_->AddVip(type, ifname, vid, address) < 0) {
        throw std::string("Can't add vip");
    }

    return SUCCESS;
}

int
controller::del_vlan_iface(const std::string &type,
                           const std::string &ifname,
                           uint32_t vid) {
    std::string vlan_ifname = ifname + "." + std::to_string(vid);
    if (client_->DelVlanIface(type, vlan_ifname, vid) < 0) {
        throw std::string("Can't del vlan interface " + ifname);
    }

    return SUCCESS;
}
