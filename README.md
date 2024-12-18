# Шифр RSA

RSA (аббревиатура от фамилий Rivest, Shamir и Adleman) — криптографический алгоритм с открытым ключом, основывающийся на вычислительной сложности задачи факторизации больших полупростых чисел. Данный код позволяет шифровать и дешифровать сообщения с помощью алгоритма RSA, также написав, какой публичный и приватный ключи были использованы в его случае.

# Описание работы приложения

## Шифрование
После запуска кода пользователю нужно ввести сообщение, которое он хочет зашифровать, и сгенерировать ключи. После нажатия кнопки на фрейм выводится зашифрованное сообщение, которое можно скопировать и вставить в поле ввода для дешифрования в случае необходимости. Шифрование текста осуществляется путем манипуляций над публичным ключом.

## Дешифрование
Не меняя сгенерированных ключей, пользователь вставляет в поле ввода для дешифрования текст из буфера обмена (или вводит сам) и, нажимая на кнопку "расшифровать", получает дешифрованный текст. В случае дешифрования используется приватный ключ.


# Пример

## Текст:
Надо было делать все лабы заранее, что-то я подустала

## Сгенерированные ключи:
Публичный: 4799 37769
Приватный: 22199 37769

## Результат шифрования:
20016 530 24888 5307 7857 33651 15368 27206 5307 7857 24888 33395 27206 530 37664 21603 7857 13604 26975 33395 7857 27206 530 33651 15368 7857 23849 530 21982 530 21960 33395 33395 21909 7857 5760 37664 5307 7255 37664 5307 7857 6926 7857 35076 5307 24888 37562 26975 37664 530 27206 530

## Результат дешифрования:
Надо было делать все лабы заранее, что-то я подустала
