# Vault OIDC Provider - Keycloak External IDP

> - https://www.keycloak.org/downloads  
> - https://www.michaelboeynaems.com/keycloak-ADFS-OIDC.html  
> - https://developer.hashicorp.com/vault/tutorials/auth-methods/oidc-identity-provider  

## 1. Run

### 1.1 Keycloak 'Dev' mode run

Keycloak [Download](https://www.keycloak.org/downloads)  페이지에서 `ZIP` 형태를 다운 받습니다.

Keycloak을 실행하기위해서는 Java가 설치되어있어야 합니다.

```bash
# https://www.keycloak.org/downloads
$ cd ${KEYCLOAK_HOME}/bin
$ KEYCLOAK_ADMIN=admin KEYCLOAK_ADMIN_PASSWORD=admin ./kc.sh start-dev
```



### 1.2 Vault 'Dev' mode run

Vault [Download](https://developer.hashicorp.com/vault/downloads) 페이지에서 실행 환경에 맞는 바이너리를 다운 받습니다.

루트 토큰을 `root` 토큰으로 사용하여 Vault 개발 서버를 시작합니다.

```bash
vault server -dev -dev-root-token-id=root -log-level=trace
```



## 2. Setup

### Type 1. Terraform

Terraform [Download](https://developer.hashicorp.com/terraform/downloads?product_intent=terraform) 페이지에서 실행 환경에 맞는 바이너리를 다운 받습니다.

첨부된 테라폼 구성에는 `Vault`와 `Keycloak` 구성의 프로비저닝의 설정이 있습니다.

테라폼 1.0 이상에서 테스트 되었습니다.

```bash
$ terraform init
$ terraform apply

...

Apply complete! Resources: 20 added, 0 changed, 0 destroyed.
```



### Type 2. Script and UI

#### Vault Env Setup

터미널 세션을 열고 볼트 CLI의 환경 변수를 지정하여 볼트 서버를 주소로 지정합니다.

```bash
export VAULT_ADDR=http://127.0.0.1:8200
```

Vault 서버와 인증할 Vault CLI의 환경 변수를 지정합니다.

```bash
export VAULT_TOKEN=root
```



#### Vault 인증 구성

userpass 인증 방법을 활성화합니다.

```bash
vault auth enable userpass
```

`user1` 사용자를 추가합니다.

```bash
vault write auth/userpass/users/user1 \
    password="password" \
    token_policies="default" \
    token_ttl="1h"
```



#### Vault ID 엔터티 및 그룹 만들기

`user1`에 대한 엔터티를 생성합니다.

```bash
vault write identity/entity \
    name="user1" \
    metadata="email=vault@hashicorp.com" \
    metadata="phone_number=123-456-7890" \
    disabled=false
```

엔터티에 할당된 ID를 `ENTITY_ID`에 할당합니다.

```bash
ENTITY_ID=$(vault read -field=id identity/entity/name/user1)
```

사용자가 구성원인 이름으로 ID 그룹을 생성합니다 .

```bash
vault write identity/group \
    name="engineering" \
    member_entity_ids="$ENTITY_ID"
```

그룹에 할당된 ID를 저장하는 이름의 변수를 만듭니다 .

```bash
GROUP_ID=$(vault read -field=id identity/group/name/engineering)
```

userpass 인증 방법의 접근자 값을 저장하는 이름이 지정된 변수를 만듭니다 .

```bash
USERPASS_ACCESSOR=$(vault read -field=accessor sys/auth/userpass)
```

`user1` 엔터티를 userpass 사용자와 매핑하는 엔터티 별칭을 만듭니다.

```bash
vault write identity/entity-alias \
    name="user1" \
    canonical_id="$ENTITY_ID" \
    mount_accessor="$USERPASS_ACCESSOR"
```



#### Vault OIDC 클라이언트 만들기

엔터티 및 그룹을 부여하는 oidc assignment를 만듭니다.

```bash
vault write identity/oidc/assignment/my-assignment \
    entity_ids="${ENTITY_ID}" \
    group_ids="${GROUP_ID}"
```

`my-key`라는 oidc 키를 생성합니다.

```bash
vault write identity/oidc/key/my-key \
    allowed_client_ids="*" \
    verification_ttl="2h" \
    rotation_period="1h" \
    algorithm="RS256"
```

OIDC 클라이언트를 만듭니다. `redirect_uris`는 Keycloak에서 구성할 `vault` realm의 `vault` idp 정보를 가정하여 생성합니다.

- e.g. : http://localhost:8080/realms/{realm_name}/broker/{idp_name}/endpoint

```bash
vault write identity/oidc/client/keycloak \
    redirect_uris="http://localhost:8080/realms/vault/broker/vault/endpoint" \
    assignments="my-assignment" \
    key="my-key" \
    id_token_ttl="30m" \
    access_token_ttl="1h"
```

Keycloak과 연동에 사용할 `client_id`와 `client_secret`을 변수로 지정합니다.

```bash
CLIENT_ID=$(vault read -field=client_id identity/oidc/client/keycloak)
CLIENT_SECRET=$(vault read -field=client_secret identity/oidc/client/keycloak)
```



#### Vault OIDC 공급자 만들기

사용자 범위 템플릿을 저장하는 명명된 변수를 만듭니다 .scope 정보에 Vault identity의 정보를 맵핑 합니다.

```bash
USER_SCOPE_TEMPLATE='{
    "username": {{identity.entity.name}},
    "contact": {
        "email": {{identity.entity.metadata.email}},
        "phone": {{identity.entity.metadata.phone_number}}
    }
}'
```

`user` 템플릿으로 명명된 Vault OIDC scope를 정의합니다 .

```bash
vault write identity/oidc/scope/user \
    description="The user scope provides claims using Vault identity entity metadata" \
    template="$(echo ${USER_SCOPE_TEMPLATE} | base64 -)"
```

그룹 범위 템플릿을 저장하는 명명된 변수를 만듭니다 .

```bash
GROUPS_SCOPE_TEMPLATE='{
    "groups": {{identity.entity.groups.names}}
}'
```

`groups` 템플릿으로 명명된 Vault OIDC scope를 정의합니다 .

```bash
vault write identity/oidc/scope/groups \
    description="The groups scope provides the groups claim using Vault group membership" \
    template="$(echo ${GROUPS_SCOPE_TEMPLATE} | base64 -)"
```

`my-provider`라는 Vault OIDC Provider를 생성합니다.

```bash
값vault write identity/oidc/provider/my-provider \
    allowed_client_ids="${CLIENT_ID}" \
    scopes_supported="groups,user"
```

다음의 경로는 Vault OIDC 구성 정보를 확인하는 경로 입니다.

```bash
curl -s $VAULT_ADDR/v1/identity/oidc/provider/my-provider/.well-known/openid-configuration | jq
```

다음의 경로는 Vault OIDC 공개키를 확인하는 경로 입니다.

```bash
curl -s $VAULT_ADDR/v1/identity/oidc/provider/my-provider/.well-known/keys | jq
```



#### Keycloak

http://localhost:8080 으로 접속하여 `Administration Console`을 선택합니다.

![image-20230531205430734](https://raw.githubusercontent.com/Great-Stone/images/master/uPic/image-20230531205430734.png)

접속을 위한 관리자 계정은 Keycloak 실행 시 부여한 환경변수 `KEYCLOAK_ADMIN`,  `KEYCLOAK_ADMIN_PASSWORD`의 값입니다.

- e.g. KEYCLOAK_ADMIN=admin
- e.g. KEYCLOAK_ADMIN_PASSWORD=admin

![image-20230531205512754](https://raw.githubusercontent.com/Great-Stone/images/master/uPic/image-20230531205512754.png)

좌측 드롭박스를 선택하여 `Create Realm` 버튼을 클릭합니다.

![image-20230531205703396](https://raw.githubusercontent.com/Great-Stone/images/master/uPic/image-20230531205703396-1.png)

`Realm name`을 `vault`로 기입하고 생성합니다.

![image-20230531205754660](https://raw.githubusercontent.com/Great-Stone/images/master/uPic/image-20230531205754660-1.png)

생성된 `vault` realm을 선택하고, 좌측 하단의 `Identity providers`를 선택하여 우측에 `Identity providers` 목록이 표기됩니다. `OpenID Connect v1.0`을 선택합니다.

![image-20230531210655772](https://raw.githubusercontent.com/Great-Stone/images/master/uPic/image-20230531210655772.png)

다음 정보를 기입하여 Oidc 설정을 완료합니다.

- Alias : vault
- Authorization URL : http://127.0.0.1:8200/ui/vault/identity/oidc/provider/my-provider/authorize
- Token URL : http://127.0.0.1:8200/v1/identity/oidc/provider/my-provider/token
- User Info URL : http://127.0.0.1:8200/v1/identity/oidc/provider/my-provider/userinfo
- Issuer : http://127.0.0.1:8200/v1/identity/oidc/provider/my-provider

- Validate Signatures : On
- Use JWKS URL : On
- JWKS URL : http://127.0.0.1:8200/v1/identity/oidc/provider/my-provider/.well-known/keys
- Client ID : Vault에서 생성한 client의 `CLIENT_ID` 값
- Client Secret : Vault에서 생성한 client의  `CLIENT_SECRET` 값
- Advanced > Scopes : engineering user



Oidc생성이 완료되면 Vault 로그인시 반환하는 Scope 값을 Keycloak Clame과 맵핑하기 위한 정보를 설정합니다. 설정한  Oidc의 `Mappers` 탭을 클릭하여 아래 정보를 추가합니다. `Claim`은  Vault에서 부여하는 Scope의 값 입니다.

![image-20230531211630134](https://raw.githubusercontent.com/Great-Stone/images/master/uPic/image-20230531211630134.png)

[username-attribute-importer]

- name : username-attribute-importer
- Sync mode override : Inherit
- Mapper type : Attribute Importer
- Claim : username
- User Attribute Name : username

[email-attribute-importer]

- name : email-attribute-importer
- Sync mode override : Inherit
- Mapper type : Attribute Importer
- Claim : contact.email
- User Attribute Name : email



## 3. Test

구성이 완료되면 Keycloak의 인증을 Vault의 인증정보로 가능한지 확인합니다. 좌측 `Clients`를 선택하고 `Clients list` 탭에서 `account`의 `Home URL`을 클릭하여 대상 realm으로의 인증을 시도합니다.

- e.g. http://localhost:8080/realms/vault/account/#/

![image-20230531212144939](https://raw.githubusercontent.com/Great-Stone/images/master/uPic/image-20230531212144939.png)

우측 상단의 `Sign in` 버튼을 클릭합니다.

![image-20230531212232175](https://raw.githubusercontent.com/Great-Stone/images/master/uPic/image-20230531212232175.png)

인증 입력 화면에서 아래 `vault` 버튼을 클릭합니다.

![image-20230531212339163](https://raw.githubusercontent.com/Great-Stone/images/master/uPic/image-20230531212339163.png)

Vault의 인증 화면으로 전환됩니다. `Method`를 `Usrname`으로 선택하고, 앞서 생성한 사용자 정보를 기입하여 인증 합니다.

- Username : user1
- Password : password

![image-20230531212509060](https://raw.githubusercontent.com/Great-Stone/images/master/uPic/image-20230531212509060.png)

인증이 성공하면 Keycloak 사용자 정보에 `Username`과 `Email`이 Vault의 Clame 값으로 자동으로 채워짐을 확인합니다. `First name`과 `Last name`을 입력하고 `Submit` 버튼을 클릭합니다.

![image-20230531212626336](https://raw.githubusercontent.com/Great-Stone/images/master/uPic/image-20230531212626336.png)

![image-20230531212916148](https://raw.githubusercontent.com/Great-Stone/images/master/uPic/image-20230531212916148.png)

Keycloak의 `Users` 항목에서 생성된 사용자 정보를 확인합니다.

![image-20230531213008606](https://raw.githubusercontent.com/Great-Stone/images/master/uPic/image-20230531213008606.png)
