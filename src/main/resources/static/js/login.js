function login(){
    var formData={
       username : document.getElementById("username").value,
       password : document.getElementById("password").value
    };
    fetch("/login", {
           method : "POST",
           headers : {
                  "Content-Type" : "application/json"
           },
           body : JSON.stringify(formData)
         })
    .then(response=>{
        if(!response.ok){
            throw new Error("Login failed");
        }
        // JWT 토큰을 받기
        var jwtToken=response.headers.get("Authorization");
        if(jwtToken && jwtToken.startsWith("Bearer ")){
             jwtToken=jwtToken.slice(7);
             localStorage.setItem("token", jwtToken);
             console.log("Received JWT token:"+jwtToken); // ?
             const authorities=jwtParsing(jwtToken);
             console.log("authorities:"+authorities); // [     ,    ]
             authorities.forEach(role=>{
                 switch(role){
                        case "ROLE_USER" :
                            document.getElementById("userMenu").style.display="block";
                            break;
                        case "ROLE_MANAGER" :
                            document.getElementById("managerMenu").style.display="block";
                            break;
                        case "ROLE_ADMIN" :
                           document.getElementById("adminMenu").style.display="block";
                           break;
                        default :
                           break;
                 }
               });  // forEach()
               // none login form | Display block
              document.getElementById("loginFom").style.display="none";
              document.getElementById("greeting").style.display="block";
              document.getElementById("usernameDisplay").innerText=formData.username;
              }else{
                      console.log("Invalid JWT token received");
             }
      })
    .catch(error=>{
       console.log("Login failed:", error);
    });
}
function jwtParsing(token){ // [0].[1],[2]
   try{
          const tokenPayload=token.split(".")[1];
          const decodedPayload=atob(tokenPayload);
          const payloadJSON=JSON.parse(decodedPayload);
          const authorities=payloadJSON.authorities;
          return authorities; // [   ]
      }catch(error){
          console.log("error");
          return [];
      }
}
function logout(){
       localStorage.removeItem("token");
        location.href="/";
}


function checkLoginStatus() {
    const token = localStorage.getItem("token");
    if (token) {
        // Token exists, authenticate user and update UI
        const authorities = jwtParsing(token);
        authorities.forEach(role => {
            switch (role) {
                case "ROLE_USER":
                    document.getElementById("userMenu").style.display = "block";
                    break;
                case "ROLE_MANAGER":
                    document.getElementById("managerMenu").style.display = "block";
                    break;
                case "ROLE_ADMIN":
                    document.getElementById("adminMenu").style.display = "block";
                    break;
                default:
                    break;
            }
        });
        // Hide login form, display greeting message
        document.getElementById("loginFom").style.display = "none";
        document.getElementById("greeting").style.display = "block";
        document.getElementById("usernameDisplay").innerText = getUsernameFromToken(token);
    }
}

function getUsernameFromToken(token) {
    try {
        const tokenPayload = token.split(".")[1];
        const decodedPayload = atob(tokenPayload);
        const payloadJSON = JSON.parse(decodedPayload);
        return payloadJSON.username;
    } catch (error) {
        console.error("Failed to extract username from token:", error);
        return "";
    }
}
    // ADMIN 메뉴 클릭 시 호출되는 함수
    function showAdminData() {
        fetchAdminData();
    }
    // 추가
    function fetchAdminData() {
        const token = localStorage.getItem("token");
        if (token) {
            fetch("/api/v1/admin", {
                method: "GET",
                headers: {
                    "Authorization": "Bearer " + token
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error("Failed to fetch admin data");
                }
                return response.text();
            })
            .then(data => {
                // 서버에서 받은 데이터 처리
                console.log("Admin data:", data);
                // 여기에 받은 데이터를 UI에 업데이트하는 코드를 추가할 수 있습니다.
                document.getElementById("detailView").innerText = "서버로부터 전송된 데이터 : "+data;
            })
            .catch(error => {
                console.error("Failed to fetch admin data:", error);
            });
        }
    }

        // MANAGE 메뉴 클릭 시 호출되는 함수
        function showManagerData() {
            fetchManagerData();
        }
        // 추가
        function fetchManagerData() {
            const token = localStorage.getItem("token");
            if (token) {
                fetch("/api/v1/manager", {
                    method: "GET",
                    headers: {
                        "Authorization": "Bearer " + token
                    }
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error("Failed to fetch manager data");
                    }
                    return response.text();
                })
                .then(data => {
                    // 서버에서 받은 데이터 처리
                    console.log("Manager data:", data);
                    // 여기에 받은 데이터를 UI에 업데이트하는 코드를 추가할 수 있습니다.
                    document.getElementById("detailView").innerText = "서버로부터 전송된 데이터 : "+data;
                })
                .catch(error => {
                    console.error("Failed to fetch manager data:", error);
                });
            }
        }

            // USER 메뉴 클릭 시 호출되는 함수
            function showUserData() {
                fetchUserData();
            }
            // 추가
            function fetchUserData() {
                const token = localStorage.getItem("token");
                if (token) {
                    fetch("/api/v1/user", {
                        method: "GET",
                        headers: {
                            "Authorization": "Bearer " + token
                        }
                    })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error("Failed to fetch user data");
                        }
                        return response.text();
                    })
                    .then(data => {
                        // 서버에서 받은 데이터 처리
                        console.log("User data:", data);
                        // 여기에 받은 데이터를 UI에 업데이트하는 코드를 추가할 수 있습니다.
                        document.getElementById("detailView").innerText = "서버로부터 전송된 데이터 : "+data;
                    })
                    .catch(error => {
                        console.error("Failed to fetch user data:", error);
                    });
                }
            }

