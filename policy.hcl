path "prod/secret/data/foo/*" {
    capabilities = ["read"]
}
    
path "prod/secret/data/foo/bar" {
    capabilities = ["update"]
}

path "prod/secret/data/foo/*" {
    capabilities = ["read"]
}
    
path "prod/secret/data/foo/bar" {
    capabilities = ["update"]
}
path "+/+/prod/secret/data/foo/*" {
    capabilities = ["read"]
}
    
#path "prod/secret/data/foo/bar" {
#    capabilities = ["update"]
#}