from androguard.core.bytecodes import apk
from collections import deque


def analyze(apk_path, coverage_dict_template):
    string_activities = '*'
    a = apk.APK(apk_path)
    main_activity, activities, services, receivers, providers = find_exported_components(a)
    androguard_activities = a.get_activities()
    app_package = a.get_package()
    exported_activities = list()
    permissions = a.get_permissions()
    for activity in androguard_activities:
        activity = activity.replace("..", ".")
        # string_activities += f'{activity}, '
        coverage_dict_template.update({activity: {'visited': False}})
        for act in activities:
            if act in activity:
                exported_activities.append(activity)
    return app_package, main_activity, exported_activities, services, receivers, providers, string_activities, \
        permissions


def find_exported_components(apk):
    main_activity = None
    activities = list()
    services = list()
    receivers = list()
    providers = list()
    for tag in [
        "activity",
        "activity-alias",
        "service",
        "receiver",
        "provider",
    ]:
        for item in apk.find_tags(tag):
            actions = deque()
            permissions = []
            name = item.get(apk._ns("name"), "")
            exported = item.get(apk._ns("exported"), "")
            permission = item.get(apk._ns("permission"), "")

            if not main_activity and tag == "activity":
                is_launchable_activity = False
                for intent in item.findall("./intent-filter"):
                    for category in intent.findall("./category"):
                        category_name = category.get(apk._ns("name"), "")
                        if category_name == "android.intent.category.LAUNCHER":
                            is_launchable_activity = True
                            break
                    if is_launchable_activity:
                        for action in intent.findall("./action"):
                            my_action = action.get(apk._ns("name"), "")
                            if my_action == "android.intent.action.MAIN":
                                main_activity = name
                                break

            if not main_activity and tag == "activity-alias":
                is_launchable_activity = False
                for intent in item.findall("./intent-filter"):
                    for category in intent.findall("./category"):
                        category_name = category.get(apk._ns("name"), "")
                        if category_name == "android.intent.category.LAUNCHER":
                            is_launchable_activity = True
                            break
                    if is_launchable_activity:
                        for action in intent.findall("./action"):
                            my_action = action.get(apk._ns("name"), "")
                            if my_action == "android.intent.action.MAIN":
                                main_activity = item.get(apk._ns("targetActivity"), "")
                                break

            if (tag == "receiver" or tag == "service") and permission != "":
                permissions.append(permission)

            # Check only components where the exported attribute is not set to
            # false explicitly.
            if name.strip() and exported.lower() != "false":
                to_check = False
                has_actions_in_intent_filter = False
                for intent in item.findall("./intent-filter"):
                    for action in intent.findall("./action"):
                        my_action = action.get(apk._ns("name"), "")
                        if (my_action != 'edu.gatech.m3.emma.COLLECT_COVERAGE') and ('END_COVERAGE' not in
                                                                                     my_action) and ('END_EMMA' not in
                                                                                                     my_action):
                            actions.append(my_action)
                            has_actions_in_intent_filter = True

                # Exported attribute is not set explicitly, but the component
                # has intent filters (so the component is exported).
                if exported == "" and has_actions_in_intent_filter:
                    to_check = True

                # Exported attribute is set to True explicitly.
                if exported.lower() == "true":
                    to_check = True

                if to_check:
                    accessible = False
                    if not permission:
                        # Exported, without any permission set.
                        accessible = True
                    else:
                        # Exported, with permission set.
                        detail = apk.get_declared_permissions_details().get(
                            permission
                        )
                        if detail:
                            level = detail["protectionLevel"]
                            if level == "None":
                                level = None
                            if (
                                    level
                                    and (
                                            int(level, 16) == 0x0
                                            or int(level, 16) == 0x1
                                    )
                            ) or not level:
                                # 0x0 is normal protectionLevel,
                                # 0x1 is dangerous protectionLevel
                                # (protectionLevel is set to normal by
                                # default).
                                accessible = True
                        else:
                            detail = apk.get_details_permissions().get(
                                permission
                            )
                            if detail:
                                level = detail[0].lower()
                                if level == "normal" or level == "dangerous":
                                    accessible = True

                    if len(permissions) > 0:
                        accessible = True

                    if accessible:
                        if (tag == "activity") or (tag == "activity-alias"):
                            activities.append(name)
                        elif tag == "service":
                            services.append({'type': 'service', 'name': name, 'action': actions, 'permissions': permissions})
                        elif tag == "receiver":
                            receivers.append({'type': 'receiver', 'name': name, 'action': actions, 'permissions': permissions})
                        elif tag == "provider":
                            providers.append({'type': 'provider', 'name': name, 'action': actions})
    return main_activity, activities, services, receivers, providers
