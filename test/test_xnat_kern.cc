#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>

#include <gtest/gtest.h>

// #include "../xnat.h"
namespace {
class test_xnat_kern : public ::testing::Test {
   protected:
    test_xnat_kern() {
    }
    ~test_xnat_kern() {
    }

    void SetUp() override{
        // xnat_ = std::make_unique<class xnat::xnat>(config_);
    };

    void
    TearDown() override {
    }

    // struct config config_ = {
    //     .prog_load_attr =
    //         {
    //             .file      = "xnat_kern.o",
    //             .prog_type = BPF_PROG_TYPE_XDP,
    //         },
    //     .xdp_flags       = XDP_FLAGS_SKB_MODE,
    //     .ingress_ifname  = "ens4",
    //     .ingress_progsec = "xnat/root/ingress",
    //     .egress_ifname   = "ens5",
    //     .egress_progsec  = "xnat/root/egress",
    //     .load_obj_name   = "xnat_kern.o",
    //     .map_pin_dir     = "/sys/fs/bpf/xnat",
    //     .pin_basedir     = "/sys/fs/bpf",
    //     .listen_address  = "0.0.0.0:10000",
    //     .rm_flag         = true,
    //     .nr_cpus         = bpf_num_possible_cpus(),
    // };

    // std::unique_ptr<class xnat::xnat> xnat_;
};
}; // namespace

TEST_F(test_xnat_kern, Checksum) {

    EXPECT_EQ(1, 1);
}

