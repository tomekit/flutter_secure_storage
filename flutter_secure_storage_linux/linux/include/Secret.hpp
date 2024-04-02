#include "FHashTable.hpp"
#include <json/json.h>
#include <libsecret/secret.h>
#include <memory>

#define secret_autofree _GLIB_CLEANUP(secret_cleanup_free)
static inline void secret_cleanup_free(gchar **p) { secret_password_free(*p); }

class SecretStorage {
  FHashTable m_attributes;
  std::string label;
  SecretSchema the_schema;

public:
  const char *getLabel() { return label.c_str(); }
  void setLabel(const char *label) { this->label = label; }

  SecretStorage(const char *_label = "default") : label(_label) {
    the_schema = {label.c_str(),
                  SECRET_SCHEMA_NONE,
                  {
                      {"account", SECRET_SCHEMA_ATTRIBUTE_STRING},
                  }};
  }

  void addAttribute(const char *key, const char *value) {
    m_attributes.insert(key, value);
  }

  bool addItem(const char *key, const char *value) {
    Json::Value root = readFromKeyring();
    root[key] = value;
    return this->storeToKeyring(root);
  }

  std::string getItem(const char *key) {
    std::string result;
    Json::Value root = readFromKeyring();
    Json::Value resultJson = root[key];
    if (resultJson.isString()) {
      result = resultJson.asString();
      return result;
    }
    return "";
  }

  void deleteItem(const char *key) {
    Json::Value root = readFromKeyring();
    root.removeMember(key);
    this->storeToKeyring(root);
  }

  bool deleteKeyring() { return this->storeToKeyring(Json::Value()); }

  bool storeToKeyring(Json::Value value) {
    Json::StreamWriterBuilder builder;
    const std::string output = Json::writeString(builder, value);
    g_autoptr(GError) err = nullptr;

    builder["indentation"] = "";

    bool result = secret_password_storev_sync(
        &the_schema, m_attributes.getGHashTable(), nullptr, label.c_str(),
        output.c_str(), nullptr, &err);

    if (err) {
      throw err->message;
    }

    return result;
  }

  Json::Value readFromKeyring() {
    Json::Value root;
    Json::CharReaderBuilder charBuilder;
    std::unique_ptr<Json::CharReader> reader(charBuilder.newCharReader());
    g_autoptr(GError) err = nullptr;

    warmupKeyring();

    secret_autofree gchar *result = secret_password_lookupv_sync(
        &the_schema, m_attributes.getGHashTable(), nullptr, &err);

    if (err) {
      throw err->message;
    }

    if (result != nullptr && strcmp(result, "") != 0 &&
      reader->parse(result, result + strlen(result), &root, NULL)) {
      return root;
    }

    this->storeToKeyring(root);
    return root;
  }

private:
  // Search with schemas fails in cold keyrings.
  // https://gitlab.gnome.org/GNOME/gnome-keyring/-/issues/89
  //
  // Note that we're not using the workaround mentioned in the above issue. Instead, we're using
  // a workaround as implemented in http://crbug.com/660005. Reason being that with the lookup
  // approach we can't distinguish whether the keyring was actually unlocked or whether the user
  // cancelled the password prompt.
  void warmupKeyring() {
    g_autoptr(GError) err = nullptr;

    FHashTable attributes;
    attributes.insert("explanation", "Because of quirks in the gnome libsecret API, "
                     "flutter_secret_storage needs to store a dummy entry to guarantee that "
                     "this keyring was properly unlocked. More details at http://crbug.com/660005.");

    const gchar* dummy_label = "FlutterSecureStorage Control";

    // Store a dummy entry without `the_schema`.
    bool success = secret_password_storev_sync(
        NULL, attributes.getGHashTable(), nullptr, dummy_label,
        "The meaning of life", nullptr, &err);

    if (!success) {
      throw "Failed to unlock the keyring";
    }
  }
};
