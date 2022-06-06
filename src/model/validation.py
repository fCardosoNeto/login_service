
def validate_params(params):
  return (params.keys().__contains__('login') and params.keys().__contains__('password'))

def diz_oi():
  return 'oi'