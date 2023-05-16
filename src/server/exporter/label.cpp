#include "label.hpp"

Label::Label(const YAML::Node& label) : decoder(label["decoder"]) {
    name = label["name"] ? label["name"].as<std::string>() : "unknown";

    std::string t = label["type"] ? label["type"].as<std::string>() : "int";

    size     = get_size_by_type(t);
    type_num = get_type_num(t);
    type     = t;
    buffer   = (char*)malloc(size);
}

Label::~Label() {
    // 暂时不知道为啥会 double free...
    // free(buffer);
}

int find_label(const std::vector<Label>& labels, const std::string& label) {
    for (auto it = labels.begin(); it != labels.end(); it++) {
        if ((*it).name == label) {
            return std::distance(labels.begin(), it);
        }
    }

    return -1;
}

// 解析 labels
std::map<std::string, std::string> parse_labels(void* p, std::vector<Label>& labels, int start) {
    std::map<std::string, std::string> map;

    for (size_t it = start; it < labels.size(); it++) {
        Label& label = labels[it];

        std::string value;

        _u64_m key = read_data_by_type((char*)p + label.offset, label.type_num, label.buffer);

        if (label.decoder.has()) {
            if (label.decoder.name == "static_map") {
                value = label.decoder.static_map(key);
            } else if (label.decoder.name == "inet") {
                // 查找协议族
                int idx = find_label(labels, "protocol");

                if (idx != -1) {
                    int af = read_data_by_type((char*)p + labels[idx].offset, labels[idx].type_num, labels[idx].buffer);
                    value  = Decoder::inet(af, (char*)p + label.offset);
                } else {
                    Log::warn("Labels missing `protocol`.");
                    value = std::to_string(key);
                }
            } else {
                Log::error("Not support decoder.\n");
                value = std::to_string(key);
            }
        } else {
            value = std::to_string(key);
        }

        map[label.name] = value;
    }

    return map;
}