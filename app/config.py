import yaml


def set_confing():

    with open("config/social_oauth.yml") as f:
        config = yaml.load(f, Loader=yaml.FullLoader)

    return config


social_oauth_cfg = set_confing()